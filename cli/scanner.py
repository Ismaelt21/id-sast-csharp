# =============================================================================
#  csharp-sast / cli / scanner.py
# =============================================================================
#
#  ORQUESTADOR CLI DEL PIPELINE PARA CSHARP-SAST
#  ──────────────────────────────────────────────
#  Punto de entrada de consola que coordina el análisis completo sobre un
#  proyecto C#:
#    • Descubrimiento de archivos .cs
#    • Análisis Roslyn del bridge .NET
#    • Importación al modelo interno
#    • Detección de framework
#    • Construcción de CFG / DFG
#    • Rule loading
#    • Taint analysis
#    • Pattern matching
#    • Framework analysis
#    • Clasificación de vulnerabilidades
#    • Reducción semántica opcional con Gemini
#    • Persistencia en MongoDB opcional
#    • Reportes JSON / HTML / SARIF / consola
#
# =============================================================================

from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ─────────────────────────────────────────────────────────────────────────────
#  BOOTSTRAP DE PATHS
# ─────────────────────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from core.ai.gemini_client import GeminiClient
from core.analyzers.csharp_pattern_matcher import CSharpPatternMatcher
from core.analyzers.framework_analyzer import FrameworkAnalyzer
from core.analyzers.semantic_analyzer import SyncSemanticAnalyzer
from core.analyzers.taint_analyzer import TaintAnalyzer
from core.analyzers.vulnerability_classifier import VulnerabilityClassifier
from core.parsers.ast_importer import AstImporter
from core.parsers.cfg_builder import CfgBuilder
from core.parsers.dfg_builder import DfgBuilder
from core.parsers.framework_detector import FrameworkDetector
from core.parsers.roslyn_client import RoslynClientConfig, SyncRoslynClient
from core.rules.rule_loader import RuleLoader
from database.analysis_repository import AnalysisRepository
from database.mongodb import MongoDB
from reports.console_report import ConsoleReport, ConsoleReportConfig
from reports.html_report import HTMLReport, HTMLReportConfig
from reports.json_report import JsonReport, ReportMetrics
from reports.sarif_report import SarifReport, SarifReportConfig
from config.settings import Settings


logger = logging.getLogger(__name__)


DEFAULT_EXCLUDES = {
    "bin",
    "obj",
    "node_modules",
    "packages",
    "dist",
    "build",
    ".git",
    ".vs",
    "TestResults",
    "coverage",
}


@dataclass
class ScannerConfig:
    """Configuración del pipeline de csharp-sast."""

    project_path: Path
    project_name: str
    output_dir: Path
    language_version: str | None = None
    reference_assemblies: list[str] = field(default_factory=list)
    use_ai: bool = True
    enable_persistence: bool = False
    quiet: bool = False
    verbose: bool = False
    no_color: bool = False
    json_only: bool = False
    html_only: bool = False
    sarif_only: bool = False
    fail_on: str = "HIGH"
    bridge_url: str | None = None
    bridge_executable: str | None = None
    include_unresolved: bool = False
    batch_size: int = 250
    scan_id: str | None = None
    tags: list[str] = field(default_factory=list)
    ci_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanOutputs:
    """Rutas generadas por el scan."""

    json_path: Path | None = None
    html_path: Path | None = None
    sarif_path: Path | None = None
    report_data: dict[str, Any] = field(default_factory=dict)
    exit_code: int = 0


class CSharpSASTScanner:
    """Orquestador síncrono del pipeline completo de análisis."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.console_report = ConsoleReport(
            ConsoleReportConfig(
                verbose=config.verbose,
                quiet=config.quiet,
                colors=not config.no_color,
                fail_on=config.fail_on,
            )
        )
        self.json_report = JsonReport()
        self.html_report = HTMLReport(HTMLReportConfig(output_dir=self.output_dir))
        self.sarif_report = SarifReport(SarifReportConfig(output_dir=self.output_dir))

        self._roslyn_config = RoslynClientConfig()
        if config.bridge_url:
            self._roslyn_config.bridge_url = config.bridge_url
        if config.bridge_executable:
            self._roslyn_config.bridge_executable = config.bridge_executable
        self._roslyn_config.include_unresolved = config.include_unresolved

        self._bridge = SyncRoslynClient(self._roslyn_config)

        self._mongo: MongoDB | None = None
        self._analysis_repo: AnalysisRepository | None = None

    def run(self) -> ScanOutputs:
        """Ejecuta el pipeline completo y devuelve las rutas de salida."""
        scan_started = time.perf_counter()
        project_path = self.config.project_path.resolve()
        files = self._discover_csharp_files(project_path)

        if not files:
            raise FileNotFoundError(
                f"No se encontraron archivos .cs en '{project_path}'"
            )

        self._maybe_setup_persistence()

        scan_id = self.config.scan_id or self._create_scan_id()
        self.config.scan_id = scan_id

        merged_export = self._analyze_with_bridge(files)
        model = AstImporter().import_from_dict(merged_export)
        profile = FrameworkDetector().detect(model)

        self.console_report.print_banner(self.config.project_name, profile)

        cfg_index = CfgBuilder().build(model)
        dfg_index = DfgBuilder().build(model)

        rules = RuleLoader().load_all()
        taint_analyzer = TaintAnalyzer(
            rules,
            cfg_index,
            dfg_index,
            framework=profile.primary_framework.value,
        )
        pattern_matcher = CSharpPatternMatcher(rules)
        framework_analyzer = FrameworkAnalyzer()
        classifier = VulnerabilityClassifier()

        self.console_report.print_phase("Pattern matching", f"{len(model.semantic_nodes)} nodos semánticos")
        pattern_findings = pattern_matcher.match(model)
        self.console_report.print_phase_done("Pattern matching", f"{len(pattern_findings)} findings")

        self.console_report.print_phase("Framework analysis", profile.primary_framework.value)
        framework_findings = framework_analyzer.analyze(model, profile)
        self.console_report.print_phase_done("Framework analysis", f"{len(framework_findings)} findings")

        self.console_report.print_phase("Taint analysis", f"{len(model.classes)} clases")
        taint_findings = taint_analyzer.analyze(model)
        self.console_report.print_phase_done("Taint analysis", f"{len(taint_findings)} findings")

        vulns = classifier.classify(
            taint_findings=taint_findings,
            pattern_findings=pattern_findings,
            framework_findings=framework_findings,
            model=model,
            profile=profile,
        )

        semantic_result = self._run_semantic_analysis(vulns, model, profile)
        final_vulns = semantic_result.enriched_vulns if semantic_result else vulns
        final_vulns = sorted(
            final_vulns,
            key=lambda v: (v.severity.sort_key, v.confidence.value if hasattr(v.confidence, "value") else str(v.confidence), v.line),
        )

        metrics = self._build_metrics(
            model=model,
            profile=profile,
            taint_findings=taint_findings,
            pattern_findings=pattern_findings,
            framework_findings=framework_findings,
            semantic_result=semantic_result,
            rules_count=len(rules),
            scan_started=scan_started,
        )

        false_positives_removed = semantic_result.false_positives if semantic_result else 0

        if self._analysis_repo and self.config.scan_id:
            try:
                self._analysis_repo.complete_scan(
                    scan_id=self.config.scan_id,
                    vulnerabilities=final_vulns,
                    metrics=dataclasses.asdict(metrics),
                    files_analyzed=[str(path) for path in files],
                    method_count=metrics.methods_analyzed,
                    node_count=metrics.nodes_analyzed,
                    graph_stats={
                        "cfg_methods": len(cfg_index.cfgs),
                        "dfg_methods": len(dfg_index.method_dfgs),
                    },
                    false_positives_removed=false_positives_removed,
                )
            except Exception as exc:
                logger.warning("No se pudo completar el análisis en MongoDB: %s", exc)

        report_exit = self._write_reports(
            final_vulns=final_vulns,
            model=model,
            profile=profile,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
            scan_id=self.config.scan_id,
        )

        console_exit = self.console_report.print_results(
            vulnerabilities=final_vulns,
            model=model,
            profile=profile,
            scan_id=self.config.scan_id,
            project_name=self.config.project_name,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )

        return ScanOutputs(
            json_path=report_exit.json_path,
            html_path=report_exit.html_path,
            sarif_path=report_exit.sarif_path,
            report_data=report_exit.report_data,
            exit_code=max(console_exit, report_exit.exit_code),
        )

    def _discover_csharp_files(self, project_path: Path) -> list[Path]:
        files: list[Path] = []
        for file_path in project_path.rglob("*.cs"):
            if any(part.lower() in DEFAULT_EXCLUDES for part in file_path.parts):
                continue
            if not file_path.is_file():
                continue
            files.append(file_path.resolve())

        files.sort()
        return files

    def _maybe_setup_persistence(self) -> None:
        if not self.config.enable_persistence:
            return

        mongo = MongoDB()
        if not mongo.connect():
            logger.debug("MongoDB no disponible; continuando sin persistencia.")
            return

        self._mongo = mongo
        self._analysis_repo = AnalysisRepository(mongo)

        try:
            self.config.scan_id = self.config.scan_id or self._analysis_repo.create_scan(
                project_name=self.config.project_name,
                project_path=str(self.config.project_path),
                framework="generic",
                language_version=self.config.language_version or "C# .NET 8",
                tags=self.config.tags,
                ci_metadata=self.config.ci_metadata,
            )
        except Exception as exc:
            logger.warning("No se pudo crear el scan en MongoDB: %s", exc)
            self.config.scan_id = self.config.scan_id or str(uuid.uuid4())

    def _create_scan_id(self) -> str:
        return str(uuid.uuid4())

    def _analyze_with_bridge(self, files: list[Path]) -> dict[str, Any]:
        batch_size = max(1, min(self.config.batch_size, self._roslyn_config.max_files_per_request))
        batches = list(_chunked(files, batch_size))

        exports: list[dict[str, Any]] = []
        total = len(files)
        done = 0

        for batch_index, batch in enumerate(batches, 1):
            current_files = [str(path) for path in batch]
            self.console_report.print_phase(
                "Roslyn bridge",
                f"batch {batch_index}/{len(batches)} | {len(batch)} archivos",
            )
            started = time.perf_counter()
            export = self._bridge.analyze(
                current_files,
                reference_assemblies=self.config.reference_assemblies or None,
                language_version=self.config.language_version,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            exports.append(export)
            done += len(batch)
            self.console_report.print_progress(
                current_file=current_files[-1] if current_files else "",
                files_done=done,
                files_total=total,
                phase=f"Roslyn {elapsed_ms:.0f} ms",
            )

        self.console_report.print_phase_done("Roslyn bridge", f"{done}/{total} archivos")
        return _merge_roslyn_exports(exports)

    def _run_semantic_analysis(
        self,
        vulns: list[Any],
        model: Any,
        profile: Any,
    ) -> Any | None:
        if not self.config.use_ai or not vulns:
            return None

        client = GeminiClient()
        analyzer = SyncSemanticAnalyzer(client, enabled=client.enabled)

        if not client.enabled:
            return None

        self.console_report.print_phase("Semantic analysis", "Gemini reduction of false positives")
        result = analyzer.analyze(vulns, model, profile)
        self.console_report.print_phase_done(
            "Semantic analysis",
            f"{result.false_positives} FP removed | {result.vulns_analyzed} analyzed",
        )
        return result

    def _build_metrics(
        self,
        *,
        model: Any,
        profile: Any,
        taint_findings: list[Any],
        pattern_findings: list[Any],
        framework_findings: list[Any],
        semantic_result: Any | None,
        rules_count: int,
        scan_started: float,
    ) -> ReportMetrics:
        metrics = ReportMetrics()
        metrics.files_analyzed = len(model.metadata.files) if hasattr(model.metadata, "files") else len(model.classes)
        metrics.methods_analyzed = sum(len(cls.methods) for cls in model.classes)
        metrics.nodes_analyzed = len(model.semantic_nodes)
        metrics.sources_found = len({v.source_label for v in taint_findings if getattr(v, "source_label", "")})
        metrics.sinks_found = len({v.sink_label for v in taint_findings if getattr(v, "sink_label", "")})
        metrics.sanitizers_found = sum(1 for v in taint_findings if getattr(v, "has_partial_sanitizer", False))
        metrics.taint_paths_analyzed = len(taint_findings)
        metrics.pattern_matches = len(pattern_findings)
        metrics.framework_findings = len(framework_findings)
        metrics.gemini_analyzed = semantic_result.vulns_analyzed if semantic_result else 0
        metrics.gemini_fp_removed = semantic_result.false_positives if semantic_result else 0
        metrics.rules_loaded = rules_count
        metrics.analysis_duration_sec = time.perf_counter() - scan_started
        return metrics

    def _write_reports(
        self,
        *,
        final_vulns: list[Any],
        model: Any,
        profile: Any,
        metrics: ReportMetrics,
        false_positives_removed: int,
        scan_id: str,
    ) -> ScanOutputs:
        outputs = ScanOutputs(exit_code=0)

        base_name = f"{self.config.project_name}_{scan_id[:8] if scan_id else 'scan'}"
        report_data = self.json_report.generate_dict(
            vulnerabilities=final_vulns,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=self.config.project_name,
            project_path=str(self.config.project_path),
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )
        outputs.report_data = report_data

        if not self.config.html_only and not self.config.sarif_only:
            json_path = self.output_dir / f"{base_name}.json"
            json_content = self.json_report.generate(
                vulnerabilities=final_vulns,
                model=model,
                profile=profile,
                scan_id=scan_id,
                project_name=self.config.project_name,
                project_path=str(self.config.project_path),
                metrics=metrics,
                false_positives_removed=false_positives_removed,
            )
            self.json_report.save(json_content, json_path)
            outputs.json_path = json_path

        if not self.config.json_only and not self.config.sarif_only:
            html_path = self.output_dir / f"{base_name}.html"
            self.html_report.generate_and_save(
                vulnerabilities=final_vulns,
                model=model,
                profile=profile,
                scan_id=scan_id,
                project_name=self.config.project_name,
                project_path=str(self.config.project_path),
                metrics=metrics,
                false_positives_removed=false_positives_removed,
                output_path=html_path,
            )
            outputs.html_path = html_path

        if not self.config.json_only and not self.config.html_only:
            sarif_path = self.output_dir / f"{base_name}.sarif"
            self.sarif_report.generate_and_save(
                vulnerabilities=final_vulns,
                model=model,
                profile=profile,
                scan_id=scan_id,
                project_name=self.config.project_name,
                project_path=str(self.config.project_path),
                metrics=metrics,
                false_positives_removed=false_positives_removed,
                output_path=sarif_path,
            )
            outputs.sarif_path = sarif_path

        report_data["report_paths"] = {
            "json": str(outputs.json_path) if outputs.json_path else "",
            "html": str(outputs.html_path) if outputs.html_path else "",
            "sarif": str(outputs.sarif_path) if outputs.sarif_path else "",
        }
        return outputs


def _chunked(items: list[Path], size: int) -> Iterable[list[Path]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _merge_roslyn_exports(exports: list[dict[str, Any]]) -> dict[str, Any]:
    if not exports:
        return {}
    if len(exports) == 1:
        return exports[0]

    merged: dict[str, Any] = {
        "metadata": {
            "files": [],
            "language_version": exports[0].get("metadata", {}).get("language_version", "Latest"),
            "framework_detected": exports[0].get("metadata", {}).get("framework_detected"),
            "nuget_references": [],
            "compilation_errors": [],
            "analysis_timestamp": exports[0].get("metadata", {}).get("analysis_timestamp", ""),
            "bridge_version": exports[0].get("metadata", {}).get("bridge_version", ""),
        },
        "compilation_unit": {"classes": []},
        "semantic_nodes": [],
        "control_flow": {"methods": []},
        "data_flow": {"assignments": [], "parameter_flows": [], "return_flows": []},
        "symbols": {"external_calls": [], "attribute_annotations": []},
    }

    for export in exports:
        metadata = export.get("metadata", {})
        merged["metadata"]["files"].extend(metadata.get("files", []))
        merged["metadata"]["nuget_references"].extend(metadata.get("nuget_references", []))
        merged["metadata"]["compilation_errors"].extend(metadata.get("compilation_errors", []))
        merged["compilation_unit"]["classes"].extend(export.get("compilation_unit", {}).get("classes", []))
        merged["semantic_nodes"].extend(export.get("semantic_nodes", []))
        merged["control_flow"]["methods"].extend(export.get("control_flow", {}).get("methods", []))
        data_flow = export.get("data_flow", {})
        merged["data_flow"]["assignments"].extend(data_flow.get("assignments", []))
        merged["data_flow"]["parameter_flows"].extend(data_flow.get("parameter_flows", []))
        merged["data_flow"]["return_flows"].extend(data_flow.get("return_flows", []))
        symbols = export.get("symbols", {})
        merged["symbols"]["external_calls"].extend(symbols.get("external_calls", []))
        merged["symbols"]["attribute_annotations"].extend(symbols.get("attribute_annotations", []))

    merged["metadata"]["files"] = list(dict.fromkeys(merged["metadata"]["files"]))
    merged["metadata"]["nuget_references"] = list(dict.fromkeys(merged["metadata"]["nuget_references"]))
    return merged


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="csharp-sast",
        description="Pipeline SAST completo para proyectos C#.",
    )
    parser.add_argument("project_path", help="Ruta al proyecto o solución C# a analizar.")
    parser.add_argument("--project-name", default=None, help="Nombre lógico del proyecto en reportes.")
    parser.add_argument("--output-dir", default=None, help="Directorio de salida para reportes.")
    parser.add_argument("--language-version", default=None, help="Versión de C# a pasar al bridge.")
    parser.add_argument("--reference-assembly", action="append", default=[], help="Ensambaldo de referencia adicional.")
    parser.add_argument("--bridge-url", default=None, help="URL del Roslyn bridge.")
    parser.add_argument("--bridge-executable", default=None, help="Ruta al ejecutable del Roslyn bridge.")
    parser.add_argument("--include-unresolved", action="store_true", help="Incluir nodos semánticos sin símbolo resuelto.")
    parser.add_argument("--batch-size", type=int, default=250, help="Cantidad de archivos por request al bridge.")
    parser.add_argument("--no-ai", action="store_true", help="Desactivar reducción semántica con Gemini.")
    parser.add_argument("--persist", action="store_true", help="Persistir el análisis en MongoDB si está disponible.")
    parser.add_argument("--quiet", action="store_true", help="Reducir la salida de consola al mínimo.")
    parser.add_argument("--verbose", action="store_true", help="Mostrar detalle completo en consola.")
    parser.add_argument("--no-color", action="store_true", help="Desactivar colores ANSI en consola.")
    parser.add_argument("--json-only", action="store_true", help="Generar solo JSON.")
    parser.add_argument("--html-only", action="store_true", help="Generar solo HTML.")
    parser.add_argument("--sarif-only", action="store_true", help="Generar solo SARIF.")
    parser.add_argument("--fail-on", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Umbral que falla el gate de CI.")
    parser.add_argument("--tag", action="append", default=[], help="Etiqueta para el scan (branch, entorno, etc.).")
    parser.add_argument("--ci-meta", action="append", default=[], metavar="KEY=VALUE", help="Metadata de CI/CD.")
    parser.add_argument("--scan-id", default=None, help="Forzar scan_id en lugar de generar uno nuevo.")
    return parser


def _parse_ci_metadata(items: list[str]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def _resolve_output_dir(project_path: Path, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path(Settings.REPORTS_DIR).resolve()


def _should_enable_persistence() -> bool:
    return Settings.USE_PERSISTENCE and bool(Settings.MONGODB_URI)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    project_path = Path(args.project_path).expanduser().resolve()
    output_dir = _resolve_output_dir(project_path, args.output_dir)
    project_name = args.project_name or project_path.name or "csharp-project"

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    config = ScannerConfig(
        project_path=project_path,
        project_name=project_name,
        output_dir=output_dir,
        language_version=args.language_version,
        reference_assemblies=args.reference_assembly,
        use_ai=not args.no_ai,
        enable_persistence=args.persist or _should_enable_persistence(),
        quiet=args.quiet,
        verbose=args.verbose,
        no_color=args.no_color,
        json_only=args.json_only,
        html_only=args.html_only,
        sarif_only=args.sarif_only,
        fail_on=args.fail_on,
        bridge_url=args.bridge_url,
        bridge_executable=args.bridge_executable,
        include_unresolved=args.include_unresolved,
        batch_size=args.batch_size,
        scan_id=args.scan_id,
        tags=args.tag,
        ci_metadata=_parse_ci_metadata(args.ci_meta),
    )

    scanner = CSharpSASTScanner(config)

    try:
        outputs = scanner.run()
    except Exception as exc:
        logger.error("Fallo ejecutando el pipeline: %s", exc)
        if args.verbose:
            traceback.print_exc()
        return 2

    return outputs.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
