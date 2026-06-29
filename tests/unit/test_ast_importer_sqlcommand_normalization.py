from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

# El clasificador importa cfg_builder, que a su vez exige networkx.
# Para esta prueba puntual basta un stub mínimo que permita importar el módulo
# sin introducir una dependencia externa en el entorno de tests.
if "networkx" not in sys.modules:
    fake_networkx = ModuleType("networkx")

    class _FakeDiGraph:  # pragma: no cover - solo para permitir imports
        pass

    fake_networkx.DiGraph = _FakeDiGraph
    fake_networkx.NodeNotFound = type("NodeNotFound", (Exception,), {})
    fake_networkx.NetworkXError = type("NetworkXError", (Exception,), {})
    fake_networkx.has_path = lambda *args, **kwargs: False
    fake_networkx.all_simple_paths = lambda *args, **kwargs: iter(())
    sys.modules["networkx"] = fake_networkx

from core.parsers.ast_importer import AstImporter
from core.analyzers.taint_analyzer import TaintFinding
from core.analyzers.csharp_pattern_matcher import SINK_PATTERNS
from core.analyzers.vulnerability_classifier import (
    Severity,
    TaintConfidence,
    VulnerabilityClassifier,
    VulnerabilityKind,
)


def test_normalize_symbol_maps_sqlcommand_constructor() -> None:
    importer = AstImporter()

    symbol = importer._normalize_symbol(
        "SqlCommand",
        "var command = new SqlCommand(sql, connection);",
    )

    assert symbol == "System.Data.SqlClient.SqlCommand..ctor"


def test_normalize_symbol_uses_resolved_type_for_ambiguous_symbols() -> None:
    importer = AstImporter()

    xml_reader = importer._normalize_symbol(
        "Create",
        "XmlReader.Create(stream, settings)",
        "System.Xml.XmlReader",
    )
    xml_document = importer._normalize_symbol(
        "Load",
        "document.Load(stream)",
        "System.Xml.XmlDocument",
    )
    from_sql_raw = importer._normalize_symbol(
        "FromSqlRaw",
        "queryable.FromSqlRaw(sql)",
        "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions",
    )
    html_string = importer._normalize_symbol(
        "HtmlString",
        "new HtmlString(rawHtml)",
        "Microsoft.AspNetCore.Html.HtmlString",
    )

    assert xml_reader == "System.Xml.XmlReader.Create"
    assert xml_document == "System.Xml.XmlDocument.Load"
    assert from_sql_raw == "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw"
    assert html_string == "Microsoft.AspNetCore.Html.HtmlString..ctor"


def test_xdocument_load_is_registered_as_xxe_sink() -> None:
    assert any(
        pattern.symbol_prefix == "System.Xml.Linq.XDocument.Load"
        and pattern.vulnerability_kind == VulnerabilityKind.XXE
        for pattern in SINK_PATTERNS
    )


def test_path_traversal_consolidation_groups_same_source_flow() -> None:
    classifier = VulnerabilityClassifier.__new__(VulnerabilityClassifier)

    base_finding = TaintFinding(
        finding_id="tf-1",
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        confidence=TaintConfidence.HIGH,
        source_node_id="source-node",
        source_symbol="Microsoft.AspNetCore.Http.IQueryCollection[indexer]",
        source_file="tests/samples/thesis_case/VulnerableThesisController.cs",
        source_line=111,
        source_label="Request.Query[\"file\"]",
        taint_label="USER_INPUT",
        sink_node_id="sink-node",
        sink_symbol="System.IO.File.ReadAllText",
        sink_file="tests/samples/thesis_case/FileService.cs",
        sink_line=36,
        sink_label="File.ReadAllText(relativePath, Encoding.UTF8)",
        sink_arg_position=0,
        method_id="method-1",
        method_name="ReadDocument",
        class_name="FileService",
        taint_path=[],
        has_partial_sanitizer=False,
        sanitizer_symbol=None,
        is_definitely_reachable=True,
        is_in_loop=False,
        raw_evidence={},
    )
    helper_finding = TaintFinding(
        finding_id="tf-2",
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        confidence=TaintConfidence.HIGH,
        source_node_id="source-node",
        source_symbol="Microsoft.AspNetCore.Http.IQueryCollection[indexer]",
        source_file="tests/samples/thesis_case/VulnerableThesisController.cs",
        source_line=111,
        source_label="Request.Query[\"file\"]",
        taint_label="USER_INPUT",
        sink_node_id="sink-node-2",
        sink_symbol="System.IO.File.Exists",
        sink_file="tests/samples/thesis_case/FileService.cs",
        sink_line=31,
        sink_label="System.IO.File.Exists(relativePath)",
        sink_arg_position=0,
        method_id="method-1",
        method_name="ReadDocument",
        class_name="FileService",
        taint_path=[],
        has_partial_sanitizer=False,
        sanitizer_symbol=None,
        is_definitely_reachable=True,
        is_in_loop=False,
        raw_evidence={},
    )
    combine_only = SimpleNamespace(
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        severity=Severity.MEDIUM,
        confidence=TaintConfidence.MEDIUM,
        file="tests/samples/thesis_case/Utilities.cs",
        line=53,
        sink_line=53,
        sink_label="Path.Combine(left, right)",
        code_snippet="Path.Combine(left, right)",
        source_label="",
        raw_evidence={},
        class_name="ThesisUtilities",
        original_findings=[],
    )

    same_flow = SimpleNamespace(
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        confidence=TaintConfidence.HIGH,
        file="tests/samples/thesis_case/FileService.cs",
        line=111,
        sink_line=36,
        sink_label="File.ReadAllText(relativePath, Encoding.UTF8)",
        code_snippet="System.IO.File.ReadAllText(relativePath, Encoding.UTF8)",
        source_label="Request.Query[\"file\"]",
        raw_evidence={},
        class_name="FileService",
        original_findings=[base_finding, helper_finding],
    )
    other_family = SimpleNamespace(
        vulnerability_kind=VulnerabilityKind.SSRF,
        severity=Severity.HIGH,
        confidence=TaintConfidence.HIGH,
        file="tests/samples/thesis_case/RemoteFetchService.cs",
        line=30,
        sink_line=30,
        sink_label="HttpClient.GetAsync(endpoint)",
        code_snippet="await _client.GetAsync(endpoint)",
        source_label="Request.Query[\"url\"]",
        raw_evidence={},
        class_name="RemoteFetchService",
        original_findings=[],
    )

    consolidated = classifier._consolidate_path_traversal_flows(
        [same_flow, other_family, combine_only]
    )

    path_findings = [
        vuln for vuln in consolidated
        if vuln.vulnerability_kind == VulnerabilityKind.PATH_TRAVERSAL
    ]
    assert len(path_findings) == 1
    assert len(path_findings[0].original_findings) == 2
    assert all(v.file != "tests/samples/thesis_case/Utilities.cs" for v in path_findings)
    assert any(v.vulnerability_kind == VulnerabilityKind.SSRF for v in consolidated)
