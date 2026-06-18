# =============================================================================
#  csharp-sast / reports / sarif_report.py
# =============================================================================
#
#  GENERADOR SARIF PARA CSHARP-SAST
#  ─────────────────────────────────
#  Exporta los resultados del análisis al estándar SARIF 2.1.0, compatible
#  con GitHub code scanning, Azure DevOps y visores enterprise.
#
#  CARACTERÍSTICAS:
#    • SARIF 2.1.0 válido y autocontenido
#    • Reglas deduplicadas por tipo de vulnerabilidad
#    • Severidad mapeada a levels SARIF
#    • Ubicaciones físicas, snippets y relatedLocations
#    • Metadatos del proyecto, framework y métricas del pipeline
#    • Reutiliza el esquema base de JsonReport para consistencia
#
#  USO:
#    report = SarifReport()
#    sarif_str = report.generate(...)
#    report.save(sarif_str, Path("reports/output/report.sarif"))
#
# =============================================================================

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.parsers.ast_importer import ParsedCSharpModel
from core.parsers.framework_detector import FrameworkProfile
from reports.json_report import JsonReport, ReportMetrics

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"


@dataclass
class SarifReportConfig:
    """Configuración del exportador SARIF."""

    output_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "output")
    filename_prefix: str = "csharp_sast_report"
    tool_name: str = "csharp-sast"
    tool_version: str = "1.0.0"


class SarifReport:
    """Exportador SARIF 2.1.0 para csharp-sast."""

    def __init__(self, config: SarifReportConfig | None = None) -> None:
        self.config = config or SarifReportConfig()
        self.config.output_dir = Path(self.config.output_dir)

    def generate(
        self,
        vulnerabilities: list[Any],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
        scan_id: str | None = None,
        project_name: str = "csharp-project",
        project_path: str = "",
        metrics: ReportMetrics | None = None,
        false_positives_removed: int = 0,
        indent: int = 2,
    ) -> str:
        """Genera el SARIF completo como string JSON."""
        report_data = JsonReport().generate_dict(
            vulnerabilities=vulnerabilities,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )
        sarif = self._build_sarif(report_data)
        return json.dumps(sarif, ensure_ascii=False, indent=indent)

    def save(self, sarif_content: str, output_path: Path) -> Path:
        """Guarda el reporte SARIF en disco."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(sarif_content, encoding="utf-8")
        logger.info("SarifReport: guardado en '%s'", output_path)
        return output_path

    def generate_and_save(
        self,
        vulnerabilities: list[Any],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
        scan_id: str | None = None,
        project_name: str = "csharp-project",
        project_path: str = "",
        metrics: ReportMetrics | None = None,
        false_positives_removed: int = 0,
        output_path: Path | None = None,
        indent: int = 2,
    ) -> Path:
        """Genera y guarda el SARIF en un único paso."""
        sarif_content = self.generate(
            vulnerabilities=vulnerabilities,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
            indent=indent,
        )

        if output_path is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = self.config.output_dir / f"{self.config.filename_prefix}_{stamp}.sarif"

        return self.save(sarif_content, output_path)

    def _build_sarif(self, report_data: dict[str, Any]) -> dict[str, Any]:
        summary = report_data.get("summary", {})
        project = report_data.get("project", {})
        metrics = report_data.get("metrics", {})
        framework_info = report_data.get("framework_info", {})
        vulns = report_data.get("vulnerabilities", []) or []
        scan_id = _text(report_data.get("scan_id", ""))
        generated_at = _iso_utc(report_data.get("generated_at"))

        rules = self._build_rules(vulns)
        results = [self._build_result(vuln) for vuln in self._sort_vulns(vulns)]

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.config.tool_name,
                            "version": self.config.tool_version,
                            "informationUri": "https://github.com/",
                            "rules": rules,
                            "properties": {
                                "schemaVersion": report_data.get("schema_version", "1.0"),
                                "projectName": project.get("name", ""),
                                "framework": project.get("framework", ""),
                            },
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": generated_at,
                            "endTimeUtc": generated_at,
                            "properties": {
                                "scanId": scan_id,
                                "projectPath": project.get("path", ""),
                                "falsePositivesRemoved": report_data.get("false_positives_info", {}).get("total_removed", 0),
                                "analysisDurationSec": metrics.get("timing", {}).get("total_sec", metrics.get("analysis_duration_sec", 0.0)),
                            },
                        }
                    ],
                    "results": results,
                    "properties": {
                        "summary": summary,
                        "metrics": metrics,
                        "frameworkInfo": framework_info,
                    },
                }
            ],
        }

    def _build_rules(self, vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for vuln in vulns:
            kind = _text(vuln.get("vulnerability_kind", "UNKNOWN"))
            grouped.setdefault(kind, []).append(vuln)

        rules: list[dict[str, Any]] = []
        for kind in sorted(grouped):
            items = grouped[kind]
            first = items[0]
            cwe = _text(first.get("cwe", ""))
            description = _text(first.get("description", ""))
            remediation = _text(first.get("remediation", ""))
            references = first.get("references", []) or []

            rules.append(
                {
                    "id": kind,
                    "name": _humanize_kind(kind),
                    "shortDescription": {"text": _text(first.get("title", kind))},
                    "fullDescription": {"text": description or _humanize_kind(kind)},
                    "helpUri": _help_uri(kind, cwe, references),
                    "help": {"text": remediation or description or _humanize_kind(kind)},
                    "defaultConfiguration": {"level": _level_for_severity(_max_severity(items))},
                    "properties": {
                        "cwe": cwe,
                        "findingSources": sorted(
                            {
                                _text(v.get("finding_source", ""))
                                for v in items
                                if _text(v.get("finding_source", ""))
                            }
                        ),
                    },
                }
            )

        return rules

    def _build_result(self, vuln: dict[str, Any]) -> dict[str, Any]:
        severity = _text(vuln.get("severity", "INFO")).upper()
        kind = _text(vuln.get("vulnerability_kind", "UNKNOWN"))
        location = vuln.get("location", {}) or {}
        file_path = _text(location.get("file", ""))
        source_line = int(location.get("source_line", 0) or 0)
        sink_line = int(location.get("sink_line", 0) or 0)
        line = sink_line or source_line or 1
        snippet = _text(vuln.get("code_snippet", ""))
        references = vuln.get("references", []) or []
        cwe = _text(vuln.get("cwe", ""))
        cwe_name = _text(vuln.get("cwe_name", ""))
        confidence = _text(vuln.get("confidence", ""))
        finding_source = _text(vuln.get("finding_source", ""))
        taint_flow = vuln.get("taint_flow", {}) or {}
        source_label = _text(taint_flow.get("source_label", ""))
        sink_label = _text(taint_flow.get("sink_label", ""))
        path_summary = taint_flow.get("path_summary", []) or []
        context = vuln.get("context", {}) or {}

        result: dict[str, Any] = {
            "ruleId": kind,
            "level": _level_for_severity(severity),
            "kind": "fail",
            "message": {
                "text": _text(vuln.get("title", kind)),
                "markdown": _text(vuln.get("description", "")) or _text(vuln.get("title", kind)),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _to_uri(file_path)},
                        "region": {
                            "startLine": line,
                            "endLine": line,
                            "snippet": {"text": snippet[:500]} if snippet else None,
                        },
                    }
                }
            ],
            "properties": {
                "vulnId": _text(vuln.get("vuln_id", "")),
                "severity": severity,
                "confidence": confidence,
                "findingSource": finding_source,
                "cwe": cwe,
                "cweName": cwe_name,
                "framework": _text(location.get("framework", "")),
                "method": _text(location.get("method", "")),
                "class": _text(location.get("class", "")),
                "sourceLine": source_line,
                "sinkLine": sink_line,
                "sourceLabel": source_label,
                "sinkLabel": sink_label,
                "taintPathSummary": path_summary[:10],
                "remediation": _text(vuln.get("remediation", "")),
                "references": references[:5],
                "context": {
                    "isInLoop": bool(context.get("is_in_loop", False)),
                    "hasPartialSanitizer": bool(context.get("has_partial_sanitizer", False)),
                    "isEntryPoint": bool(context.get("is_entry_point", False)),
                },
            },
        }

        related_locations = []
        if source_line and source_line != line:
            related_locations.append(
                {
                    "id": 1,
                    "physicalLocation": {
                        "artifactLocation": {"uri": _to_uri(file_path)},
                        "region": {"startLine": source_line, "endLine": source_line},
                    },
                    "message": {"text": source_label or "Taint source"},
                }
            )
        if sink_line:
            related_locations.append(
                {
                    "id": 2,
                    "physicalLocation": {
                        "artifactLocation": {"uri": _to_uri(file_path)},
                        "region": {"startLine": sink_line, "endLine": sink_line},
                    },
                    "message": {"text": sink_label or "Taint sink"},
                }
            )

        if related_locations:
            result["relatedLocations"] = related_locations

        return result

    @staticmethod
    def _sort_vulns(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(
            vulns,
            key=lambda v: (
                order.get(_text(v.get("severity", "INFO")).upper(), 99),
                _text(v.get("location", {}).get("file", "")),
                int(v.get("location", {}).get("sink_line", 0) or 0),
                _text(v.get("vuln_id", "")),
            ),
        )


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _iso_utc(value: Any) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    return str(value)


def _max_severity(vulns: list[dict[str, Any]]) -> str:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    best = "INFO"
    best_rank = 4
    for vuln in vulns:
        sev = _text(vuln.get("severity", "INFO")).upper()
        rank = order.get(sev, 4)
        if rank < best_rank:
            best = sev
            best_rank = rank
    return best


def _level_for_severity(severity: str) -> str:
    sev = severity.upper()
    if sev in {"CRITICAL", "HIGH"}:
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _humanize_kind(kind: str) -> str:
    return kind.replace("_", " ").title() if kind else "Unknown"


def _help_uri(kind: str, cwe: str, references: list[Any]) -> str:
    if references:
        return _text(references[0])
    if cwe.upper().startswith("CWE-"):
        suffix = cwe.split("-", 1)[-1]
        if suffix.isdigit():
            return f"https://cwe.mitre.org/data/definitions/{suffix}.html"
    slug = kind.replace("_", "-").lower()
    return f"https://owasp.org/www-community/attacks/{slug}"


def _to_uri(path: str) -> str:
    if not path:
        return ""
    if path.startswith("file:"):
        return path
    try:
        return Path(path).resolve().as_uri()
    except Exception:
        return path.replace("\\", "/")