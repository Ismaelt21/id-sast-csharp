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
from core.analyzers.vulnerability_classifier import (
    VulnerabilityClassifier,
    Severity,
    TaintConfidence,
    VulnerabilityKind,
)


def test_normalize_symbol_maps_sqlcommand_constructor() -> None:
    importer = AstImporter()

    symbol = importer._normalize_symbol(
        "SqlCommand",
        "var command = new SqlCommand(sql, connection);",
    )

    assert symbol == "System.Data.SqlClient.SqlCommand..ctor"


def test_path_traversal_helper_heuristic_flags_only_helper_methods() -> None:
    classifier = VulnerabilityClassifier()

    helper_vuln = SimpleNamespace(
        method_name="ResolveFilePath",
        class_name="FileService",
        sink_label="Path.Combine(_rootDirectory, relative)",
        code_snippet="Path.Combine(_rootDirectory, relative)",
    )
    direct_vuln = SimpleNamespace(
        method_name="ReadDocument",
        class_name="FileService",
        sink_label="System.IO.File.ReadAllText(relativePath, Encoding.UTF8)",
        code_snippet="System.IO.File.ReadAllText(relativePath, Encoding.UTF8)",
    )

    assert classifier._is_path_traversal_helper(helper_vuln)
    assert not classifier._is_path_traversal_helper(direct_vuln)


def test_path_traversal_consolidation_keeps_one_helper_chain_finding() -> None:
    classifier = VulnerabilityClassifier()

    helper_vuln = SimpleNamespace(
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        method_name="ResolveFilePath",
        class_name="FileService",
        severity=Severity.HIGH,
        confidence=TaintConfidence.HIGH,
        line=36,
        original_findings=["helper"],
    )
    direct_vuln = SimpleNamespace(
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        method_name="ReadDocument",
        class_name="FileService",
        severity=Severity.HIGH,
        confidence=TaintConfidence.HIGH,
        line=31,
        original_findings=["direct"],
    )
    other_vuln = SimpleNamespace(
        vulnerability_kind=VulnerabilityKind.SSRF,
        method_name="Fetch",
        class_name="RemoteFetchService",
        severity=Severity.HIGH,
        confidence=TaintConfidence.HIGH,
        line=30,
        original_findings=["other"],
    )

    consolidated = classifier._consolidate_path_traversal_helpers(
        [helper_vuln, direct_vuln, other_vuln]
    )

    assert len(consolidated) == 2
    path_findings = [
        vuln for vuln in consolidated
        if vuln.vulnerability_kind == VulnerabilityKind.PATH_TRAVERSAL
    ]
    assert len(path_findings) == 1
    assert sorted(path_findings[0].original_findings) == ["direct", "helper"]
