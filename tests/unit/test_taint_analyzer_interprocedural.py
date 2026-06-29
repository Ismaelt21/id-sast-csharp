from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

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

from core.analyzers.taint_analyzer import TaintAnalyzer


def _method(method_id: str, name: str, parameters: list[str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        method_id=method_id,
        name=name,
        return_type="string",
        parameters=[SimpleNamespace(name=param) for param in (parameters or [])],
    )


def _node(node_id: str, kind: str, resolved_symbol: str, line: int, arguments=None) -> SimpleNamespace:
    return SimpleNamespace(
        node_id=node_id,
        kind=kind,
        resolved_symbol=resolved_symbol,
        line=line,
        arguments=arguments or [],
    )


def test_tainted_return_methods_expand_transitively() -> None:
    analyzer = TaintAnalyzer.__new__(TaintAnalyzer)

    method_c = _method("mC", "BuildHelper")
    method_b = _method("mB", "BuildBuilder")
    method_a = _method("mA", "ControllerEntry")

    model = SimpleNamespace(
        classes=[
            SimpleNamespace(name="HelperClass", methods=[method_c]),
            SimpleNamespace(name="BuilderClass", methods=[method_b]),
            SimpleNamespace(name="ControllerClass", methods=[method_a]),
        ],
        methods_by_id={"mA": method_a, "mB": method_b, "mC": method_c},
        nodes_by_id={},
        nodes_by_method={
            "mA": [
                _node("call-b", "InvocationExpression", "BuilderClass.BuildBuilder", 10),
                _node("ret-a", "ReturnStatement", "return", 12),
            ],
            "mB": [
                _node("call-c", "InvocationExpression", "HelperClass.BuildHelper", 20),
                _node("ret-b", "ReturnStatement", "return", 22),
            ],
            "mC": [],
        },
        return_flows=[
            SimpleNamespace(method_id="mC", returned_node_ids=["ret-c"], may_return_tainted=True),
            SimpleNamespace(method_id="mB", returned_node_ids=["ret-b"], may_return_tainted=False),
            SimpleNamespace(method_id="mA", returned_node_ids=["ret-a"], may_return_tainted=False),
        ],
    )
    model.nodes_by_id = {
        "call-b": model.nodes_by_method["mA"][0],
        "ret-a": model.nodes_by_method["mA"][1],
        "call-c": model.nodes_by_method["mB"][0],
        "ret-b": model.nodes_by_method["mB"][1],
        "ret-c": _node("ret-c", "ReturnStatement", "return", 30),
    }

    tainted_returns = analyzer._collect_tainted_return_methods(model)

    assert tainted_returns == {"mA", "mB", "mC"}


def test_tainted_return_origin_marks_callee_parameter() -> None:
    analyzer = TaintAnalyzer.__new__(TaintAnalyzer)

    method_c = _method("mC", "BuildHelper")
    method_b = _method("mB", "BuildBuilder")
    method_a = _method("mA", "ControllerEntry")
    method_d = _method("mD", "HelperSink", ["query"])

    arg_from_builder = SimpleNamespace(
        position=0,
        text="builderResult",
        resolved_type="string",
        is_literal=False,
        data_flow_origin="unknown",
        origin_parameter_name=None,
        origin_node_id="call-b",
        named_parameter=None,
        may_be_tainted=False,
    )

    model = SimpleNamespace(
        classes=[
            SimpleNamespace(name="HelperClass", methods=[method_c]),
            SimpleNamespace(name="BuilderClass", methods=[method_b]),
            SimpleNamespace(name="ControllerClass", methods=[method_a]),
            SimpleNamespace(name="SinkClass", methods=[method_d]),
        ],
        methods_by_id={"mA": method_a, "mB": method_b, "mC": method_c, "mD": method_d},
        nodes_by_id={},
        nodes_by_method={
            "mA": [
                _node("call-b", "InvocationExpression", "BuilderClass.BuildBuilder", 10),
                _node("call-d", "InvocationExpression", "SinkClass.HelperSink", 14, [arg_from_builder]),
                _node("ret-a", "ReturnStatement", "return", 16),
            ],
            "mB": [
                _node("call-c", "InvocationExpression", "HelperClass.BuildHelper", 20),
                _node("ret-b", "ReturnStatement", "return", 22),
            ],
            "mC": [],
            "mD": [],
        },
        return_flows=[
            SimpleNamespace(method_id="mC", returned_node_ids=["ret-c"], may_return_tainted=True),
            SimpleNamespace(method_id="mB", returned_node_ids=["ret-b"], may_return_tainted=False),
            SimpleNamespace(method_id="mA", returned_node_ids=["ret-a"], may_return_tainted=False),
            SimpleNamespace(method_id="mD", returned_node_ids=[], may_return_tainted=False),
        ],
    )
    model.nodes_by_id = {
        "call-b": model.nodes_by_method["mA"][0],
        "call-d": model.nodes_by_method["mA"][1],
        "ret-a": model.nodes_by_method["mA"][2],
        "call-c": model.nodes_by_method["mB"][0],
        "ret-b": model.nodes_by_method["mB"][1],
        "ret-c": _node("ret-c", "ReturnStatement", "return", 30),
    }

    tainted_returns = analyzer._collect_tainted_return_methods(model)
    tainted_params = analyzer._collect_tainted_callee_parameters(model, tainted_returns)

    assert tainted_returns == {"mA", "mB", "mC"}
    assert tainted_params == {"mD": {"query"}}


def test_read_request_body_helper_is_treated_as_tainted_return() -> None:
    analyzer = TaintAnalyzer.__new__(TaintAnalyzer)

    method = _method("mRead", "ReadRequestBody")
    model = SimpleNamespace(
        classes=[SimpleNamespace(name="ThesisController", methods=[method])],
        methods_by_id={"mRead": method},
        nodes_by_id={
            "ret-read": _node("ret-read", "ReturnStatement", "return", 18),
        },
        nodes_by_method={
            "mRead": [
                _node("copy-body", "InvocationExpression", "Request.Body.CopyTo", 12),
                _node("ret-read", "ReturnStatement", "return", 18),
            ]
        },
        return_flows=[
            SimpleNamespace(
                method_id="mRead",
                returned_node_ids=["ret-read"],
                may_return_tainted=False,
            )
        ],
    )

    assert analyzer._method_returns_tainted(
        method,
        tainted_return_methods=set(),
        model=model,
    )
