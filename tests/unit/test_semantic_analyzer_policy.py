from __future__ import annotations

from core.analyzers.semantic_analyzer import GeminiVerdict, SemanticAnalyzer
from core.analyzers.taint_analyzer import TaintConfidence, VulnerabilityKind
from core.analyzers.vulnerability_classifier import (
    ClassifiedVulnerability,
    CvssVector,
    FindingSource,
    Severity,
)


def _sample_ssrf_vulnerability() -> ClassifiedVulnerability:
    return ClassifiedVulnerability(
        vuln_id="abc123deadbeef00",
        finding_source=FindingSource.TAINT_ANALYSIS,
        vulnerability_kind=VulnerabilityKind.SSRF,
        severity=Severity.CRITICAL,
        confidence=TaintConfidence.HIGH,
        cwe="CWE-918",
        cwe_name="Server-Side Request Forgery",
        cvss=CvssVector(base_score=9.1, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
        file=r"tests\samples\ssrf\VulnerableSsrfController.cs",
        line=27,
        sink_line=29,
        code_snippet="var url = Request.Query[\"url\"].ToString();",
        method_name="Fetch",
        class_name="VulnerableSsrfController",
        framework="aspnetcore",
        title="Server-Side Request Forgery — URL controlada por el usuario",
        description="desc",
        remediation="remediate",
        references=[],
        source_label="Request.Query",
        sink_label="_http.GetAsync(url)",
        taint_path_summary=["L27: Request.Query", "L29: _http.GetAsync(url)"],
        is_in_loop=False,
        has_partial_sanitizer=False,
        is_entry_point=True,
    )


def test_gemini_fp_suggestion_does_not_remove_high_severity_vuln() -> None:
    analyzer = SemanticAnalyzer.__new__(SemanticAnalyzer)
    vuln = _sample_ssrf_vulnerability()
    verdict = GeminiVerdict(
        vuln_id=vuln.vuln_id,
        is_false_positive=True,
        confidence_adjusted=None,
        severity_adjusted=None,
        reasoning="Looks safe, but this is only a suggestion.",
        enriched_description=None,
        enriched_remediation=None,
        suggested_fix=None,
    )

    enriched, confirmed, false_positives = analyzer._apply_verdicts([vuln], [verdict])

    assert len(enriched) == 1
    assert enriched[0].vuln_id == vuln.vuln_id
    assert confirmed == 1
    assert false_positives == 0
    assert enriched[0].raw_evidence["gemini_is_false_positive_suggested"] is True
