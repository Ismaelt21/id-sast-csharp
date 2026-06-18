from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from id_sast_csharp.core.models.scan_request import ScanRequest
from id_sast_csharp.core.models.scan_result import ScanResult
from id_sast_csharp.infrastructure.config.settings import Settings
from id_sast_csharp.infrastructure.reporting.report_service import ReportService


class AnalysisPipeline:
    """
    Thin orchestration layer.

    This package is prepared to wrap the existing scanner
    implementation while we evolve toward a clean microservice.
    """

    def run(self, request: ScanRequest) -> ScanResult:
        try:
            from cli.scanner import CSharpSASTScanner, ScannerConfig
        except Exception as exc:  # pragma: no cover - bootstrap guard
            raise RuntimeError(
                "Legacy scanner could not be imported."
            ) from exc

        project_path = request.resolved_project_path()
        project_name = project_path.name or "csharp-project"
        output_dir = Path(request.output_directory or Settings.REPORTS_DIR).resolve()
        bridge_executable = self._resolve_bridge_executable()

        config = ScannerConfig(
            project_path=project_path,
            project_name=project_name,
            output_dir=output_dir,
            use_ai=request.use_ai,
            enable_persistence=request.persist and Settings.USE_PERSISTENCE,
            quiet=not request.verbose,
            verbose=request.verbose,
            no_color=False,
            json_only=request.json_only,
            html_only=request.html_only,
            sarif_only=request.sarif_only,
            fail_on="HIGH",
            bridge_url=None,
            bridge_executable=bridge_executable,
            include_unresolved=False,
            batch_size=250,
            scan_id=None,
            tags=[],
            ci_metadata={},
        )

        scanner = CSharpSASTScanner(config)
        outputs = scanner.run()
        persisted = bool(getattr(scanner, "_analysis_repo", None))

        report = self._load_report(outputs.json_path)

        scan_id = (
            scanner.config.scan_id
            or report.get("metadata", {}).get("scan_id")
            or "SCAN_LOCAL"
        )
        result = self._build_scan_result(
            report=report,
            scan_id=scan_id,
            default_project_name=project_name,
            report_path=outputs.json_path,
            request=request,
            persisted=persisted,
        )
        return result

    def load_scan(self, scan_id: str) -> ScanResult:
        loaded = ReportService().load_report(scan_id)
        if not loaded:
            raise FileNotFoundError(f"Scan report not found for scan_id={scan_id}")

        report, report_path = loaded
        return self._build_scan_result(
            report=report,
            scan_id=scan_id,
            default_project_name=report.get("project", {}).get("name", "csharp-project"),
            report_path=report_path,
            request=None,
        )

    def _load_report(self, json_path: Path | None) -> Dict[str, Any]:
        if not json_path:
            return {}

        if not json_path.exists():
            return {}

        with json_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _build_scan_result(
        self,
        report: Dict[str, Any],
        scan_id: str,
        default_project_name: str,
        report_path: Path | None,
        request: ScanRequest | None,
        persisted: bool = False,
    ) -> ScanResult:
        project = report.get("project", {}) or {}
        summary = report.get("summary", {}) or {}
        vulnerabilities = report.get("vulnerabilities", []) or []
        framework_info = report.get("framework_info", {}) or {}
        metrics = report.get("metrics", {}) or {}
        findings = [self._normalize_finding(vuln) for vuln in vulnerabilities]
        severity = summary.get("by_severity", {}) or {}

        return ScanResult(
            scan_id=scan_id,
            status="completed",
            project_name=project.get("name", default_project_name),
            files_scanned=project.get("files_analyzed", metrics.get("files_analyzed", 0)),
            findings_count=summary.get("total_vulnerabilities", len(findings)),
            critical=severity.get("critical", severity.get("CRITICAL", 0)),
            high=severity.get("high", severity.get("HIGH", 0)),
            medium=severity.get("medium", severity.get("MEDIUM", 0)),
            low=severity.get("low", severity.get("LOW", 0)),
            framework=project.get("framework") or framework_info.get("primary"),
            reports={
                "json": str(report_path) if report_path else "",
                "html": "",
                "sarif": "",
            },
            findings=findings,
            ai={
                "summary": summary,
                "framework_info": framework_info,
                "metrics": metrics,
                "enabled": bool(request.use_ai) if request else False,
            },
            database={"persisted": persisted},
            report=report,
            report_path=str(report_path) if report_path else None,
        )

    def _resolve_bridge_executable(self) -> str | None:
        candidates = [
            Path(Settings.BASE_DIR) / "roslyn_bridge" / "bin" / "Release" / "net8.0" / "win-x64" / "RoslynBridge.exe",
            Path(Settings.BASE_DIR) / "roslyn_bridge" / "publish" / "RoslynBridge.exe",
        ]

        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        return None

    def _normalize_finding(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        location = vulnerability.get("location", {}) or {}
        taint_flow = vulnerability.get("taint_flow", {}) or {}

        return {
            "id": vulnerability.get("vuln_id"),
            "vulnerability": vulnerability.get("vulnerability_kind"),
            "severity": vulnerability.get("severity"),
            "confidence": vulnerability.get("confidence"),
            "source": taint_flow.get("source_label", ""),
            "sink": taint_flow.get("sink_label", ""),
            "sink_label": taint_flow.get("sink_label", ""),
            "cwe_id": vulnerability.get("cwe"),
            "title": vulnerability.get("title"),
            "description": vulnerability.get("description"),
            "remediation": vulnerability.get("remediation"),
            "references": vulnerability.get("references", []),
            "code_snippet": vulnerability.get("code_snippet"),
            "metadata": {
                "finding_source": vulnerability.get("finding_source"),
                "cvss": vulnerability.get("cvss", {}),
                "context": vulnerability.get("context", {}),
                "taint_flow": taint_flow,
                "location": location,
            },
        }
