# =============================================================================
#  csharp-sast / reports / json_report.py
# =============================================================================
#
#  GENERADOR DE REPORTE JSON PARA CSHARP-SAST
#  ─────────────────────────────────────────────
#  Genera el reporte de análisis en formato JSON estructurado.
#  Es el formato base que alimenta al resto de reportes (HTML, SARIF,
#  console) y que se persiste en MongoDB via AnalysisRepository.
#
#  DISEÑO:
#    • El JSON generado es determinista (misma entrada → mismo output)
#    • Incluye metadatos del análisis, resumen ejecutivo y detalle completo
#    • Cada vulnerabilidad tiene un vuln_id estable (hash file+line+symbol)
#    • El formato es human-readable con indentación configurable
#    • Compatible con herramientas de CI/CD que parsean JSON (jq, Python, etc.)
#
#  ESTRUCTURA DEL JSON:
#    {
#      "schema_version": "1.0",
#      "scan_id": "uuid",
#      "project": { ... },
#      "summary": { ... },
#      "vulnerabilities": [ ... ],
#      "metrics": { ... },
#      "remediation_summary": { ... },
#      "false_positives_info": { ... }
#    }
#
#  USO:
#    report = JsonReport()
#    json_str = report.generate(
#        scan_id=scan_id,
#        vulnerabilities=classified_vulns,
#        model=model,
#        profile=profile,
#        metrics=metrics,
#    )
#    report.save(json_str, Path("output/report.json"))
#
# =============================================================================

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.parsers.ast_importer import ParsedCSharpModel
from core.parsers.framework_detector import FrameworkProfile

logger = logging.getLogger(__name__)

REPORT_SCHEMA_VERSION = "1.0"


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE ENTRADA
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReportMetrics:
    """
    Métricas del pipeline de análisis para incluir en el reporte.
    Recolectadas por scanner.py durante la ejecución.
    """
    files_analyzed:        int = 0
    methods_analyzed:      int = 0
    nodes_analyzed:        int = 0
    sources_found:         int = 0
    sinks_found:           int = 0
    sanitizers_found:      int = 0
    taint_paths_analyzed:  int = 0
    pattern_matches:       int = 0
    framework_findings:    int = 0
    gemini_analyzed:       int = 0
    gemini_fp_removed:     int = 0
    rules_loaded:          int = 0
    analysis_duration_sec: float = 0.0
    roslyn_bridge_ms:      float = 0.0
    taint_analysis_ms:     float = 0.0
    pattern_analysis_ms:   float = 0.0
    gemini_analysis_ms:    float = 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  GENERADOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class JsonReport:
    """
    Generador de reporte JSON para csharp-sast.

    Convierte la lista de ClassifiedVulnerability más el contexto del análisis
    en un documento JSON estructurado y completo.
    """

    # ─────────────────────────────────────────────────────────────────────────
    #  API PÚBLICA
    # ─────────────────────────────────────────────────────────────────────────

    def generate(
        self,
        vulnerabilities:    list[Any],        # list[ClassifiedVulnerability]
        model:              ParsedCSharpModel,
        profile:            FrameworkProfile,
        scan_id:            str | None = None,
        project_name:       str = "csharp-project",
        project_path:       str = "",
        metrics:            ReportMetrics | None = None,
        false_positives_removed: int = 0,
        indent:             int = 2,
    ) -> str:
        """
        Genera el reporte JSON completo como string.

        Args:
            vulnerabilities:         list[ClassifiedVulnerability] del VulnerabilityClassifier.
            model:                   ParsedCSharpModel del AstImporter.
            profile:                 FrameworkProfile del FrameworkDetector.
            scan_id:                 UUID del análisis (None = auto-generado).
            project_name:            Nombre del proyecto para el reporte.
            project_path:            Ruta del proyecto en disco.
            metrics:                 Métricas del pipeline (opcional).
            false_positives_removed: FPs removidos por Gemini/SemanticAnalyzer.
            indent:                  Indentación JSON (2 = human-readable).

        Returns:
            String JSON completo del reporte.
        """
        metrics = metrics or ReportMetrics()

        # Serializar todas las vulnerabilidades
        vulns_serialized = [
            self._serialize_vulnerability(v)
            for v in vulnerabilities
        ]

        # Construir el documento completo
        report = {
            "schema_version":       REPORT_SCHEMA_VERSION,
            "scan_id":              scan_id or self._generate_scan_id(),
            "generated_at":         _now_iso(),
            "project":              self._build_project_section(
                                        project_name, project_path, model, profile
                                    ),
            "summary":              self._build_summary(
                                        vulns_serialized, false_positives_removed
                                    ),
            "vulnerabilities":      vulns_serialized,
            "metrics":              self._build_metrics_section(metrics),
            "remediation_summary":  self._build_remediation_summary(vulns_serialized),
            "false_positives_info": self._build_fp_info(false_positives_removed, metrics),
            "framework_info":       self._build_framework_section(profile),
        }

        json_str = json.dumps(report, ensure_ascii=False, indent=indent)

        logger.info(
            "JsonReport: reporte generado — %d vulns, %.1f KB",
            len(vulns_serialized),
            len(json_str) / 1024,
        )
        return json_str

    def generate_dict(
        self,
        vulnerabilities:    list[Any],
        model:              ParsedCSharpModel,
        profile:            FrameworkProfile,
        scan_id:            str | None = None,
        project_name:       str = "csharp-project",
        project_path:       str = "",
        metrics:            ReportMetrics | None = None,
        false_positives_removed: int = 0,
    ) -> dict[str, Any]:
        """
        Genera el reporte como dict Python (sin serializar a string).
        Útil para pasar directamente a MongoDB o a otros generadores de reporte.
        """
        json_str = self.generate(
            vulnerabilities=vulnerabilities,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )
        return json.loads(json_str)

    def save(
        self,
        json_content: str,
        output_path:  Path,
    ) -> Path:
        """
        Guarda el reporte JSON en disco.

        Args:
            json_content: String JSON del reporte (de generate()).
            output_path:  Ruta de salida (.json).

        Returns:
            Path al archivo guardado.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            f.write(json_content)

        size_kb = output_path.stat().st_size / 1024
        logger.info(
            "JsonReport: guardado en '%s' (%.1f KB)",
            output_path, size_kb,
        )
        return output_path

    def generate_and_save(
        self,
        vulnerabilities:    list[Any],
        model:              ParsedCSharpModel,
        profile:            FrameworkProfile,
        output_path:        Path,
        scan_id:            str | None = None,
        project_name:       str = "csharp-project",
        project_path:       str = "",
        metrics:            ReportMetrics | None = None,
        false_positives_removed: int = 0,
    ) -> Path:
        """Shortcut que genera y guarda el reporte en un solo paso."""
        json_str = self.generate(
            vulnerabilities=vulnerabilities,
            model=model,
            profile=profile,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            metrics=metrics,
            false_positives_removed=false_positives_removed,
        )
        return self.save(json_str, output_path)

    # ─────────────────────────────────────────────────────────────────────────
    #  SECCIONES DEL REPORTE
    # ─────────────────────────────────────────────────────────────────────────

    def _build_project_section(
        self,
        project_name: str,
        project_path: str,
        model:        ParsedCSharpModel,
        profile:      FrameworkProfile,
    ) -> dict[str, Any]:
        """Sección de metadata del proyecto analizado."""
        files = list(model.metadata.files) if hasattr(model.metadata, "files") else []

        return {
            "name":             project_name,
            "path":             project_path,
            "framework":        profile.primary_framework.value,
            "language_version": getattr(model.metadata, "language_version", "C# .NET 8"),
            "files_analyzed":   len(files),
            "methods_analyzed": sum(
                len(cls.methods) for cls in model.classes
            ),
            "classes_analyzed": len(model.classes),
            "target_frameworks": [
                fw.value for fw in profile.detected_frameworks
            ] if hasattr(profile, "detected_frameworks") else [profile.primary_framework.value],
        }

    def _build_summary(
        self,
        vulns:                   list[dict[str, Any]],
        false_positives_removed: int,
    ) -> dict[str, Any]:
        """Resumen ejecutivo del análisis."""
        # Conteo por severidad
        by_severity: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        by_kind:     dict[str, int] = {}
        by_cwe:      dict[str, int] = {}
        by_file:     dict[str, int] = {}
        by_confidence: dict[str, int] = {}

        for v in vulns:
            sev  = v.get("severity", "INFO")
            kind = v.get("vulnerability_kind", "UNKNOWN")
            cwe  = v.get("cwe", "?")
            file = _basename(v.get("location", {}).get("file", "?")) or "?"
            conf = v.get("confidence", "low")

            by_severity[sev]         = by_severity.get(sev, 0) + 1
            by_kind[kind]            = by_kind.get(kind, 0) + 1
            by_cwe[cwe]              = by_cwe.get(cwe, 0) + 1
            by_file[file]            = by_file.get(file, 0) + 1
            by_confidence[conf]      = by_confidence.get(conf, 0) + 1

        total = len(vulns)

        # Top 5 archivos más afectados
        top_files = sorted(
            [{"file": k, "count": v} for k, v in by_file.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:5]

        # Top 5 tipos de vulnerabilidad
        top_kinds = sorted(
            [{"kind": k, "count": v} for k, v in by_kind.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:5]

        # Determinar nivel de riesgo global
        risk_level = _calculate_risk_level(by_severity)

        return {
            "total_vulnerabilities":    total,
            "false_positives_removed":  false_positives_removed,
            "risk_level":               risk_level,
            "by_severity": {
                "critical": by_severity.get("CRITICAL", 0),
                "high":     by_severity.get("HIGH", 0),
                "medium":   by_severity.get("MEDIUM", 0),
                "low":      by_severity.get("LOW", 0),
                "info":     by_severity.get("INFO", 0),
            },
            "by_vulnerability_kind": by_kind,
            "by_cwe":                by_cwe,
            "by_confidence":         by_confidence,
            "top_affected_files":    top_files,
            "top_vulnerability_types": top_kinds,
        }

    def _build_metrics_section(self, metrics: ReportMetrics) -> dict[str, Any]:
        """Sección de métricas del pipeline de análisis."""
        return {
            "files_analyzed":       metrics.files_analyzed,
            "methods_analyzed":     metrics.methods_analyzed,
            "nodes_analyzed":       metrics.nodes_analyzed,
            "sources_found":        metrics.sources_found,
            "sinks_found":          metrics.sinks_found,
            "sanitizers_found":     metrics.sanitizers_found,
            "taint_paths_analyzed": metrics.taint_paths_analyzed,
            "pattern_matches":      metrics.pattern_matches,
            "framework_findings":   metrics.framework_findings,
            "gemini": {
                "findings_sent":      metrics.gemini_analyzed,
                "false_positives_removed": metrics.gemini_fp_removed,
            },
            "rules_loaded":         metrics.rules_loaded,
            "timing": {
                "total_sec":         round(metrics.analysis_duration_sec, 2),
                "roslyn_bridge_ms":  round(metrics.roslyn_bridge_ms, 0),
                "taint_analysis_ms": round(metrics.taint_analysis_ms, 0),
                "pattern_analysis_ms": round(metrics.pattern_analysis_ms, 0),
                "gemini_ms":         round(metrics.gemini_analysis_ms, 0),
            },
        }

    def _build_remediation_summary(
        self,
        vulns: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Resumen de remediaciones agrupadas por tipo de vulnerabilidad.
        Permite al desarrollador ver qué tipos de fixes necesita hacer.
        """
        # Agrupar remediaciones únicas por tipo de vuln
        remediations: dict[str, list[str]] = {}

        for v in vulns:
            kind       = v.get("vulnerability_kind", "UNKNOWN")
            remediation = v.get("remediation", "")

            if kind not in remediations:
                remediations[kind] = []

            # Solo incluir remediaciones únicas
            if remediation and remediation not in remediations[kind]:
                remediations[kind].append(remediation)

        # Construir sección con conteo y primeras remediaciones
        result: dict[str, Any] = {}
        for kind, rems in sorted(remediations.items()):
            count = sum(1 for v in vulns if v.get("vulnerability_kind") == kind)
            result[kind] = {
                "count":              count,
                "primary_remediation": rems[0] if rems else "",
                "references":         self._get_references_for_kind(kind),
            }

        return result

    def _build_fp_info(
        self,
        false_positives_removed: int,
        metrics:                 ReportMetrics,
    ) -> dict[str, Any]:
        """Información sobre el proceso de reducción de falsos positivos."""
        total_analyzed = metrics.gemini_analyzed
        reduction_pct = (
            round(false_positives_removed / total_analyzed * 100, 1)
            if total_analyzed > 0
            else 0.0
        )
        return {
            "total_removed":            false_positives_removed,
            "findings_sent_to_gemini":  total_analyzed,
            "reduction_percentage":     reduction_pct,
            "gemini_enabled":           total_analyzed > 0,
        }

    def _build_framework_section(self, profile: FrameworkProfile) -> dict[str, Any]:
        """Información del framework detectado para contexto del reporte."""
        return {
            "primary":              profile.primary_framework.value,
            "detected_frameworks":  [
                fw.value for fw in profile.detected_frameworks
            ] if hasattr(profile, "detected_frameworks") else [],
            "nuget_packages":       getattr(profile, "nuget_packages", [])[:20],
            "is_aspnetcore":        getattr(profile, "is_aspnetcore", False),
            "is_wcf":               getattr(profile, "is_wcf", False),
            "has_ef_core":          getattr(profile, "has_ef_core", False),
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  SERIALIZACIÓN DE VULNERABILIDADES
    # ─────────────────────────────────────────────────────────────────────────

    def _serialize_vulnerability(self, vuln: Any) -> dict[str, Any]:
        """
        Serializa una ClassifiedVulnerability a dict JSON-serializable.

        Usa getattr para acceder a los campos — evita import circular
        con vulnerability_classifier.py.
        """
        def _get(attr: str, default: Any = None) -> Any:
            return getattr(vuln, attr, default)

        def _enum_val(attr: str, default: str = "") -> str:
            val = getattr(vuln, attr, None)
            if val is None:
                return default
            return val.value if hasattr(val, "value") else str(val)

        # ID estable
        vuln_id = _get("vuln_id") or self._stable_id(
            _get("file", ""),
            _get("sink_line", 0),
            _enum_val("vulnerability_kind"),
        )

        # CVSS
        cvss = _get("cvss")
        cvss_data = {
            "base_score":    getattr(cvss, "base_score", 0.0) if cvss else 0.0,
            "vector_string": getattr(cvss, "vector_string", "") if cvss else "",
        }

        # Taint path summary (lista de strings)
        taint_path = _get("taint_path_summary", []) or []

        # Referencias
        references = _get("references", []) or []

        return {
            "vuln_id":              vuln_id,
            "vulnerability_kind":   _enum_val("vulnerability_kind"),
            "severity":             _enum_val("severity"),
            "confidence":           _enum_val("confidence"),
            "finding_source":       _enum_val("finding_source"),
            "cwe":                  _get("cwe", ""),
            "cwe_name":             _get("cwe_name", ""),
            "cvss":                 cvss_data,
            "location": {
                "file":             _get("file", ""),
                "file_short":       _get("file", "").split("/")[-1],
                "source_line":      _get("line", 0),
                "sink_line":        _get("sink_line", 0),
                "method":           _get("method_name", ""),
                "class":            _get("class_name", ""),
                "framework":        _get("framework", ""),
            },
            "title":                _get("title", ""),
            "description":          _get("description", ""),
            "remediation":          _get("remediation", ""),
            "references":           references,
            "taint_flow": {
                "source_label":     _get("source_label", ""),
                "sink_label":       _get("sink_label", ""),
                "path_summary":     taint_path[:10],
            },
            "context": {
                "is_in_loop":           _get("is_in_loop", False),
                "has_partial_sanitizer": _get("has_partial_sanitizer", False),
                "is_entry_point":        _get("is_entry_point", False),
            },
            "code_snippet":         _get("code_snippet", "")[:300],
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _stable_id(file: str, line: int, kind: str) -> str:
        key = f"{file}:{line}:{kind}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def _generate_scan_id() -> str:
        import uuid
        return str(uuid.uuid4())

    @staticmethod
    def _get_references_for_kind(kind: str) -> list[str]:
        """Retorna referencias OWASP/CWE relevantes para el tipo de vulnerabilidad."""
        refs: dict[str, list[str]] = {
            "SQL_INJECTION": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            "COMMAND_INJECTION": [
                "https://owasp.org/www-community/attacks/Command_Injection",
            ],
            "PATH_TRAVERSAL": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
            ],
            "XSS": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            "RAZOR_XSS": [
                "https://owasp.org/www-community/attacks/xss/",
            ],
            "SSRF": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            ],
            "XXE": [
                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            ],
            "INSECURE_DESERIALIZATION": [
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
            ],
            "OPEN_REDIRECT": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            ],
        }
        return refs.get(kind, [])


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS DE MÓDULO
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _calculate_risk_level(by_severity: dict[str, int]) -> str:
    """
    Calcula el nivel de riesgo global del proyecto basado en las severidades.

    CRITICAL > HIGH > MEDIUM > LOW > CLEAN
    """
    if by_severity.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if by_severity.get("HIGH", 0) > 0:
        return "HIGH"
    if by_severity.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if by_severity.get("LOW", 0) > 0:
        return "LOW"
    return "CLEAN"