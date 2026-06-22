# =============================================================================
#  csharp-sast / core / parsers / dfg_builder.py
# =============================================================================
#
#  CONSTRUCTOR DEL DATA FLOW GRAPH (DFG) ESPECIALIZADO PARA C#
#  ──────────────────────────────────────────────────────────────
#  Construye el grafo de dependencias de datos para el taint analysis.
#
#  EL DFG REPRESENTA:
#    Qué valores fluyen hacia dónde dentro y entre métodos.
#    Si el valor de un parámetro llega a un sink, hay una vulnerabilidad potencial.
#
#  NODOS DEL DFG:
#    • ParameterNode   → parámetro de un método (posible source de taint)
#    • SemanticNode    → invocación / creación de objeto
#    • AssignmentNode  → variable local / campo que recibe un valor
#    • ReturnNode      → valor de retorno de un método
#
#  ARISTAS DEL DFG:
#    • "flows_to"    → el dato del nodo origen fluye al nodo destino
#    • "aliases"     → dos variables apuntan al mismo dato
#    • "assigned_to" → el valor se asigna a esta variable
#    • "returned_by" → el valor viene del retorno de este método
#
#  ANÁLISIS INTER-PROCEDURAL:
#    Si GetUserInput() retorna datos tainted, todas las variables que
#    reciban su valor también están tainted.
#    Esto es crítico para detectar vulns en código bien estructurado
#    donde los datos pasan a través de capas (Controller → Service → Repo).
#
#  FEATURES ESPECÍFICOS DE C#:
#    • Tracking a través de async/await (continuaciones)
#    • Propagación en colecciones List<T>, Dictionary<K,V>
#    • String interpolation: $"SELECT * WHERE id={userId}"
#    • String concatenation: "SELECT" + userId
#    • Alias transitivo: var query = id; SqlCommand(query)
#    • Lambda captures: () => SqlCommand(capturedVar)
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Iterator

try:
    import networkx as nx
except ImportError:
    raise ImportError("NetworkX es requerido. Instala con: pip install networkx")

from .ast_importer import (
    AssignmentInfo,
    CSharpSemanticNode,
    ParameterFlow,
    ParsedCSharpModel,
    ReturnFlow,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  TIPOS DE NODO Y ARISTA EN EL DFG
# ─────────────────────────────────────────────────────────────────────────────

class DfgNodeKind(Enum):
    PARAMETER = auto()       # Parámetro de un método
    SEMANTIC_NODE = auto()   # Invocación / objeto creado
    ASSIGNMENT = auto()      # Variable local o campo
    RETURN_VALUE = auto()    # Valor retornado por un método
    STRING_BUILD = auto()    # String interpolado o concatenado (riesgo especial)
    COLLECTION = auto()      # Elemento añadido a una colección
    LAMBDA_CAPTURE = auto()  # Variable capturada por una lambda


class DfgEdgeKind(Enum):
    FLOWS_TO = "flows_to"       # El dato fluye hacia este nodo
    ALIASES = "aliases"         # Son el mismo dato (alias)
    ASSIGNED_TO = "assigned_to" # El valor se asigna a esta variable
    RETURNED_BY = "returned_by" # El valor viene de este retorno
    CAPTURED_BY = "captured_by" # La variable es capturada por una lambda


@dataclass
class DfgNode:
    """Nodo del DFG con toda la información necesaria para el taint analysis."""
    node_id: str           # ID único en el DFG
    kind: DfgNodeKind
    label: str             # Nombre descriptivo (para reportes y debug)
    method_id: str | None
    line: int
    file: str

    # Para nodos de tipo SEMANTIC_NODE
    semantic_node: CSharpSemanticNode | None = None

    # Para nodos de tipo PARAMETER
    parameter_name: str | None = None
    parameter_type: str | None = None

    # Para nodos de tipo ASSIGNMENT
    variable_name: str | None = None
    variable_type: str | None = None
    is_literal: bool = False

    # Taint state (establecido por el taint_analyzer)
    taint_label: str | None = None  # None = no tainted

    def __repr__(self) -> str:
        return f"DfgNode({self.kind.name}:{self.label!r}@L{self.line})"


@dataclass
class TaintPath:
    """
    Camino de taint desde un source hasta un sink.
    Incluye la lista de nodos intermedios del DFG.
    """
    source_node_id: str
    sink_node_id: str
    path_nodes: list[str]       # IDs de DfgNode en el camino
    has_sanitizer: bool = False
    sanitizer_node_id: str | None = None

    @property
    def is_sanitized(self) -> bool:
        return self.has_sanitizer and self.sanitizer_node_id is not None


# ─────────────────────────────────────────────────────────────────────────────
#  GRAFO DFG DE UN MÉTODO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MethodDfg:
    """
    DFG de un método individual.
    Cada método tiene su propio grafo; el inter-procedural analysis
    los conecta a través de ReturnFlows.
    """
    method_id: str
    method_name: str
    graph: nx.DiGraph

    # Índices rápidos
    nodes_by_id: dict[str, DfgNode] = field(default_factory=dict, repr=False)

    # Nodos de parámetros (posibles sources de taint)
    parameter_nodes: list[str] = field(default_factory=list)  # DfgNode IDs

    # Nodos sink conocidos en este método
    sink_nodes: list[str] = field(default_factory=list)  # DfgNode IDs

    def get_node(self, dfg_node_id: str) -> DfgNode | None:
        return self.nodes_by_id.get(dfg_node_id)

    def successors(self, dfg_node_id: str) -> list[DfgNode]:
        return [
            self.nodes_by_id[nid]
            for nid in self.graph.successors(dfg_node_id)
            if nid in self.nodes_by_id
        ]

    def predecessors(self, dfg_node_id: str) -> list[DfgNode]:
        return [
            self.nodes_by_id[nid]
            for nid in self.graph.predecessors(dfg_node_id)
            if nid in self.nodes_by_id
        ]

    def iter_taint_candidates(self) -> Iterator[tuple[DfgNode, DfgNode]]:
        """
        Itera pares (source_param, sink_node) que son candidatos de taint.
        El taint_analyzer los evalúa para determinar si son vulnerabilidades.
        """
        for param_id in self.parameter_nodes:
            for sink_id in self.sink_nodes:
                param_node = self.nodes_by_id.get(param_id)
                sink_node = self.nodes_by_id.get(sink_id)
                if param_node and sink_node:
                    yield param_node, sink_node

    def find_taint_paths(
        self, source_dfg_id: str, sink_dfg_id: str, max_paths: int = 5
    ) -> list[list[str]]:
        """Encuentra caminos en el DFG desde source hasta sink."""
        try:
            paths = list(nx.all_simple_paths(
                self.graph, source_dfg_id, sink_dfg_id, cutoff=15
            ))
            return paths[:max_paths]
        except (nx.NodeNotFound, nx.NetworkXError):
            return []

    def __repr__(self) -> str:
        return (
            f"MethodDfg(method={self.method_name!r}, "
            f"nodes={self.graph.number_of_nodes()}, "
            f"edges={self.graph.number_of_edges()}, "
            f"params={len(self.parameter_nodes)}, "
            f"sinks={len(self.sink_nodes)})"
        )


@dataclass
class ProjectDfgIndex:
    """
    Índice de todos los DFGs del proyecto, incluyendo el grafo inter-procedural.
    """
    method_dfgs: dict[str, MethodDfg] = field(default_factory=dict)

    # Grafo inter-procedural: conecta ReturnFlows con llamadas
    inter_procedural_graph: nx.DiGraph = field(
        default_factory=nx.DiGraph, repr=False
    )

    def get(self, method_id: str) -> MethodDfg | None:
        return self.method_dfgs.get(method_id)

    def __len__(self) -> int:
        return len(self.method_dfgs)

    def __iter__(self) -> Iterator[MethodDfg]:
        return iter(self.method_dfgs.values())


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTRUCTOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class DfgBuilder:
    """
    Construye los DFGs desde el ParsedCSharpModel.

    Uso:
        builder = DfgBuilder()
        dfg_index = builder.build(model)
        method_dfg = dfg_index.get(method_id)
    """

    def build(self, model: ParsedCSharpModel) -> ProjectDfgIndex:
        """
        Construye el índice DFG completo del proyecto.

        Args:
            model: ParsedCSharpModel del AstImporter.

        Returns:
            ProjectDfgIndex con un MethodDfg por método y el grafo
            inter-procedural que los conecta.
        """
        index = ProjectDfgIndex()
        total_methods = 0
        failed = 0

        # ── 1. Construir DFG intra-procedural por método ───────────────────
        for cls in model.classes:
            for method in cls.methods:
                total_methods += 1
                try:
                    dfg = self._build_method_dfg(method.method_id, method.name, model)
                    index.method_dfgs[method.method_id] = dfg
                except Exception as exc:
                    failed += 1
                    logger.warning(
                        "No se pudo construir DFG para %s: %s", method.name, exc
                    )

        # ── 2. Construir grafo inter-procedural ────────────────────────────
        self._build_inter_procedural_graph(index, model)

        logger.info(
            "DFG construido: %d/%d métodos exitosos, %d fallidos. "
            "Grafo inter-procedural: %d nodos, %d aristas.",
            total_methods - failed,
            total_methods,
            failed,
            index.inter_procedural_graph.number_of_nodes(),
            index.inter_procedural_graph.number_of_edges(),
        )
        return index

    # ─────────────────────────────────────────────────────────────────────────
    #  DFG INTRA-PROCEDURAL
    # ─────────────────────────────────────────────────────────────────────────

    def _build_method_dfg(
        self, method_id: str, method_name: str, model: ParsedCSharpModel
    ) -> MethodDfg:
        """Construye el DFG de un método individual."""
        g = nx.DiGraph()
        g.graph["method_id"] = method_id
        g.graph["method_name"] = method_name

        nodes_by_id: dict[str, DfgNode] = {}
        param_node_ids: list[str] = []
        sink_node_ids: list[str] = []

        method_info = model.methods_by_id.get(method_id)
        if not method_info:
            return MethodDfg(method_id, method_name, g, nodes_by_id)

        # ── A. Nodos de parámetros ─────────────────────────────────────────
        param_flows = model.param_flows_by_method.get(method_id, [])
        param_flow_by_name: dict[str, ParameterFlow] = {
            pf.parameter_name: pf for pf in param_flows
        }

        for param in method_info.parameters:
            dfg_id = f"param_{method_id}_{param.name}"
            node = DfgNode(
                node_id=dfg_id,
                kind=DfgNodeKind.PARAMETER,
                label=f"{method_name}.{param.name}",
                method_id=method_id,
                line=method_info.line_start,
                file=method_info.file,
                parameter_name=param.name,
                parameter_type=param.resolved_type,
            )
            g.add_node(dfg_id, **self._node_attrs(node))
            nodes_by_id[dfg_id] = node
            param_node_ids.append(dfg_id)

        # ── B. Nodos semánticos (invocaciones y creaciones) ───────────────
        semantic_nodes = model.nodes_by_method.get(method_id, [])
        semantic_dfg_ids: dict[str, str] = {}  # semantic_node_id → dfg_id

        parameter_names = {param.name for param in method_info.parameters}
        for sn in semantic_nodes:
            dfg_id = f"sn_{sn.node_id}"
            node = DfgNode(
                node_id=dfg_id,
                kind=DfgNodeKind.SEMANTIC_NODE,
                label=sn.text[:80],
                method_id=method_id,
                line=sn.line,
                file=sn.file,
                semantic_node=sn,
            )
            g.add_node(dfg_id, **self._node_attrs(node))
            nodes_by_id[dfg_id] = node
            semantic_dfg_ids[sn.node_id] = dfg_id

            if sn.is_known_sink:
                sink_node_ids.append(dfg_id)

        # ── C. Conectar parámetros → nodos semánticos ─────────────────────
        for param in method_info.parameters:
            param_dfg_id = f"param_{method_id}_{param.name}"
            pf = param_flow_by_name.get(param.name)
            if not pf:
                continue

            # Conexiones directas: param es usado como argumento en un nodo
            for used_node_id in pf.used_in_node_ids:
                sn_dfg_id = semantic_dfg_ids.get(used_node_id)
                if sn_dfg_id:
                    g.add_edge(
                        param_dfg_id, sn_dfg_id,
                        edge_kind=DfgEdgeKind.FLOWS_TO.value,
                        parameter_name=param.name,
                    )

        # ── D. Nodos de asignaciones ──────────────────────────────────────
        assignments = model.assignments_by_method.get(method_id, [])
        assignment_dfg_ids: dict[str, str] = {}  # assignment_id → dfg_id

        for asgn in assignments:
            # Ignorar asignaciones con origen literal (seguras)
            if asgn.is_literal:
                continue

            dfg_id = f"asgn_{asgn.assignment_id}"
            is_special = asgn.target_name.startswith("__")

            node_kind = DfgNodeKind.ASSIGNMENT
            if asgn.target_name.startswith("__interpolated"):
                node_kind = DfgNodeKind.STRING_BUILD
            elif asgn.target_name.startswith("__string_concat"):
                node_kind = DfgNodeKind.STRING_BUILD
            elif asgn.target_name.startswith("__collection"):
                node_kind = DfgNodeKind.COLLECTION
            elif asgn.target_name.startswith("__lambda_capture"):
                node_kind = DfgNodeKind.LAMBDA_CAPTURE

            node = DfgNode(
                node_id=dfg_id,
                kind=node_kind,
                label=f"{asgn.target_name} = {asgn.source_text[:50]}",
                method_id=method_id,
                line=asgn.line,
                file="",
                variable_name=asgn.target_name,
                variable_type=asgn.target_type,
                is_literal=asgn.is_literal,
            )
            g.add_node(dfg_id, **self._node_attrs(node))
            nodes_by_id[dfg_id] = node
            assignment_dfg_ids[asgn.assignment_id] = dfg_id

            # Conectar el source del assignment al nodo de asignación
            if asgn.source_node_id:
                source_dfg_id = semantic_dfg_ids.get(asgn.source_node_id)
                if source_dfg_id:
                    g.add_edge(
                        source_dfg_id, dfg_id,
                        edge_kind=DfgEdgeKind.ASSIGNED_TO.value,
                    )

        # ── E. Conectar asignaciones → semantic nodes (alias tracking) ────
        # Si var x = param; y luego SqlCommand(x), conectar param → x → SqlCommand
        self._connect_aliases(
            g, method_id, assignments, semantic_nodes,
            param_node_ids, assignment_dfg_ids, semantic_dfg_ids,
            nodes_by_id, model,
        )

        # ── F. Conectar argumentos de semantic nodes ──────────────────────
        # Para cada argumento que viene de un parámetro o variable,
        # conectar el origen al nodo semántico
        for sn in semantic_nodes:
            sn_dfg_id = semantic_dfg_ids.get(sn.node_id)
            if not sn_dfg_id:
                continue

            for arg in sn.arguments:
                if arg.is_literal:
                    continue

                if arg.is_from_parameter and arg.origin_parameter_name:
                    param_dfg_id = f"param_{method_id}_{arg.origin_parameter_name}"
                    if param_dfg_id in nodes_by_id:
                        g.add_edge(
                            param_dfg_id, sn_dfg_id,
                            edge_kind=DfgEdgeKind.FLOWS_TO.value,
                            arg_position=arg.position,
                        )
                elif arg.data_flow_origin == "field":
                    field_base = self._field_access_parameter_name(arg.text, parameter_names)
                    if field_base:
                        param_dfg_id = f"param_{method_id}_{field_base}"
                        if param_dfg_id in nodes_by_id:
                            g.add_edge(
                                param_dfg_id, sn_dfg_id,
                                edge_kind=DfgEdgeKind.FLOWS_TO.value,
                                arg_position=arg.position,
                                via_field=arg.text,
                            )

                elif arg.is_from_return_value and arg.origin_node_id:
                    origin_dfg_id = semantic_dfg_ids.get(arg.origin_node_id)
                    if origin_dfg_id:
                        g.add_edge(
                            origin_dfg_id, sn_dfg_id,
                            edge_kind=DfgEdgeKind.FLOWS_TO.value,
                            arg_position=arg.position,
                        )

        # ── G. Conectar source nodes → assignments que los contienen ──────────────
        # El bridge no siempre popula source_node_id en assignments cuando
        # el source está encadenado (Request.Query["id"].ToString()).
        # Conectamos por: si el source_text del assignment contiene el texto
        # del source node Y están en la misma línea.
        for sn in semantic_nodes:
            if not sn.is_known_source:
                continue
            sn_dfg_id = semantic_dfg_ids.get(sn.node_id)
            if not sn_dfg_id:
                continue

            for asgn in assignments:
                if asgn.is_literal:
                    continue
                asgn_dfg_id = assignment_dfg_ids.get(asgn.assignment_id)
                if not asgn_dfg_id:
                    continue

                # Conectar si el assignment está en la misma línea que el source
                # o si el source_text contiene el texto del source node
                same_line = (asgn.line == sn.line)
                text_contains = sn.text and sn.text[:30] in asgn.source_text

                if same_line or text_contains:
                    g.add_edge(
                        sn_dfg_id, asgn_dfg_id,
                        edge_kind=DfgEdgeKind.FLOWS_TO.value,
                        via_source=True,
                    )

        # ── H. Conectar assignments → sink nodes por variable ─────────────────────
        sanitizer_lines_by_var: dict[str, list[int]] = {}
        for sn in semantic_nodes:
            if not sn.is_known_sanitizer:
                continue
            for arg in sn.arguments:
                if not arg.is_literal:
                    sanitizer_lines_by_var.setdefault(arg.text, []).append(sn.line)

        var_to_asgn_dfg_local: dict[str, str] = {}
        for asgn in assignments:
            if not asgn.is_literal:
                dfg_id = assignment_dfg_ids.get(asgn.assignment_id)
                if dfg_id:
                    var_to_asgn_dfg_local[asgn.target_name] = dfg_id

        for sn in semantic_nodes:
            if not sn.is_known_sink:
                continue
            sn_dfg_id = semantic_dfg_ids.get(sn.node_id)
            if not sn_dfg_id:
                continue
            for arg in sn.arguments:
                if arg.is_literal:
                    continue
                asgn_dfg_id = var_to_asgn_dfg_local.get(arg.text)
                if not asgn_dfg_id or g.has_edge(asgn_dfg_id, sn_dfg_id):
                    continue

                # Si hay un sanitizador que usa esta variable antes del sink → no conectar
                san_lines = sanitizer_lines_by_var.get(arg.text, [])
                asgn_node = nodes_by_id.get(asgn_dfg_id)
                asgn_line = asgn_node.line if asgn_node else 0
                sanitized = any(asgn_line <= sl <= sn.line for sl in san_lines)

                if not sanitized:
                    # Si el primer argumento del sink es literal → la query está parametrizada
                    first_arg_is_literal = (
                        len(sn.arguments) > 0 and sn.arguments[0].is_literal
                    )
                    if first_arg_is_literal:
                        continue
                    g.add_edge(
                        asgn_dfg_id, sn_dfg_id,
                        edge_kind=DfgEdgeKind.FLOWS_TO.value,
                        via_variable=arg.text,
                    )

        return MethodDfg(
            method_id=method_id,
            method_name=method_name,
            graph=g,
            nodes_by_id=nodes_by_id,
            parameter_nodes=param_node_ids,
            sink_nodes=sink_node_ids,
        )

    def _field_access_parameter_name(
        self,
        arg_text: str,
        parameter_names: set[str],
    ) -> str | None:
        """
        Devuelve el parámetro base para accesos simples `param.Prop`.
        """
        text = (arg_text or "").strip()
        if "." not in text:
            return None

        base = text.split(".", 1)[0].strip()
        if base in parameter_names:
            return base

        return None

    def _connect_aliases(
        self,
        g: nx.DiGraph,
        method_id: str,
        assignments: list[AssignmentInfo],
        semantic_nodes: list[CSharpSemanticNode],
        param_node_ids: list[str],
        assignment_dfg_ids: dict[str, str],
        semantic_dfg_ids: dict[str, str],
        nodes_by_id: dict[str, DfgNode],
        model: ParsedCSharpModel,
    ) -> None:
        """
        Conecta los flujos de alias en el DFG.

        Escenario: var query = userId; SqlCommand(query)
            → El assignment 'query = userId' conecta param:userId → asgn:query
            → El nodo SqlCommand(query) tiene arg origin "local_variable"
            → Debemos conectar asgn:query → SemanticNode:SqlCommand

        También maneja string interpolation y concatenación:
            $"SELECT WHERE id={userId}" → riesgo de SQL injection
        """
        # Construir mapa: variable_name → DfgNode de asignación
        var_to_asgn_dfg: dict[str, str] = {}
        for asgn in assignments:
            dfg_id = assignment_dfg_ids.get(asgn.assignment_id)
            if dfg_id:
                var_to_asgn_dfg[asgn.target_name] = dfg_id

        # Conectar parámetros → assignments que los usan
        param_flows = model.param_flows_by_method.get(method_id, [])
        for pf in param_flows:
            param_dfg_id = f"param_{method_id}_{pf.parameter_name}"
            if param_dfg_id not in nodes_by_id:
                continue

            for asgn_id in pf.assigned_to_ids:
                # asgn_id aquí es el node_id de la asignación (no assignment_id)
                # Buscar la asignación por source_node_id
                for asgn in assignments:
                    if asgn.source_node_id == asgn_id:
                        asgn_dfg_id = assignment_dfg_ids.get(asgn.assignment_id)
                        if asgn_dfg_id:
                            g.add_edge(
                                param_dfg_id, asgn_dfg_id,
                                edge_kind=DfgEdgeKind.ALIASES.value,
                                parameter_name=pf.parameter_name,
                            )

        # Conectar assignments → semantic nodes que usan esa variable
        for sn in semantic_nodes:
            sn_dfg_id = semantic_dfg_ids.get(sn.node_id)
            if not sn_dfg_id:
                continue

            for arg in sn.arguments:
                if arg.data_flow_origin == "local_variable":
                    # Buscar si hay un assignment para esta variable
                    asgn_dfg_id = var_to_asgn_dfg.get(arg.text)
                    if asgn_dfg_id:
                        g.add_edge(
                            asgn_dfg_id, sn_dfg_id,
                            edge_kind=DfgEdgeKind.FLOWS_TO.value,
                            arg_position=arg.position,
                            via_alias=arg.text,
                        )

        # ── Conectar string builds → semantic nodes que los reciben
        for asgn in assignments:
            if asgn.target_name in ("__interpolated_string", "__string_concat"):
                asgn_dfg_id = assignment_dfg_ids.get(asgn.assignment_id)
                if not asgn_dfg_id:
                    continue
                for sn in semantic_nodes:
                    if sn.is_known_sink and abs(sn.line - asgn.line) <= 2:
                        sn_dfg_id = semantic_dfg_ids.get(sn.node_id)
                        if sn_dfg_id:
                            # ── FIX: no conectar si el sink tiene primer argumento literal ──
                            # SqlCommand("SELECT ... @id", conn) → query parametrizada → seguro
                            if sn.arguments and sn.arguments[0].is_literal:
                                continue
                            g.add_edge(
                                asgn_dfg_id, sn_dfg_id,
                                edge_kind=DfgEdgeKind.FLOWS_TO.value,
                                string_build=True,
                            )

    # ─────────────────────────────────────────────────────────────────────────
    #  GRAFO INTER-PROCEDURAL
    # ─────────────────────────────────────────────────────────────────────────

    def _build_inter_procedural_graph(
        self, index: ProjectDfgIndex, model: ParsedCSharpModel
    ) -> None:
        """
        Construye el grafo inter-procedural que conecta los DFGs de métodos.

        Escenario:
          string GetUserId() { return Request.Query["id"]; }   // source
          void SaveUser()    { var id = GetUserId(); Sql(id); } // sink via call

        El inter-procedural graph conecta:
          ReturnNode(GetUserId) → AssignmentNode(id) → SinkNode(Sql)
        """
        ipg = index.inter_procedural_graph

        # Construir mapa: method_name → method_id para búsqueda rápida
        method_by_name: dict[str, str] = {}
        for cls in model.classes:
            for method in cls.methods:
                method_by_name[method.name] = method.method_id
                method_by_name[method.signature] = method.method_id

        # Para cada ReturnFlow que puede retornar datos tainted
        return_flow_by_method: dict[str, ReturnFlow] = {
            rf.method_id: rf for rf in model.return_flows
        }

        for method_dfg in index.method_dfgs.values():
            for sn_dfg_id in list(method_dfg.graph.nodes):
                dfg_node = method_dfg.nodes_by_id.get(sn_dfg_id)
                if not dfg_node or dfg_node.kind != DfgNodeKind.SEMANTIC_NODE:
                    continue

                sn = dfg_node.semantic_node
                if not sn:
                    continue

                # Buscar si esta invocación llama a un método del proyecto
                called_method_id = self._find_called_method(sn, method_by_name, model)
                if not called_method_id:
                    continue

                called_return = return_flow_by_method.get(called_method_id)
                if not called_return or not called_return.may_return_tainted:
                    continue

                # Añadir nodos y arista al grafo inter-procedural
                caller_node_id = f"caller_{sn.node_id}"
                callee_return_id = f"return_{called_method_id}"

                if not ipg.has_node(caller_node_id):
                    ipg.add_node(caller_node_id, method_id=method_dfg.method_id, kind="caller")
                if not ipg.has_node(callee_return_id):
                    ipg.add_node(
                        callee_return_id,
                        method_id=called_method_id,
                        kind="return",
                        may_return_tainted=True,
                    )

                ipg.add_edge(
                    callee_return_id,
                    caller_node_id,
                    edge_kind=DfgEdgeKind.RETURNED_BY.value,
                    called_method_id=called_method_id,
                )

                logger.debug(
                    "Inter-procedural: %s puede retornar tainted a %s",
                    called_method_id[:8],
                    sn.text[:40],
                )

    def _find_called_method(
        self,
        sn: CSharpSemanticNode,
        method_by_name: dict[str, str],
        model: ParsedCSharpModel,
    ) -> str | None:
        """
        Intenta encontrar el method_id del método llamado por este nodo.
        Usa el resolved_symbol del nodo para match preciso.
        """
        if not sn.resolved_symbol:
            return None

        # Match por símbolo resuelto (más preciso)
        for cls in model.classes:
            for method in cls.methods:
                expected_suffix = f"{cls.name}.{method.name}"
                # Match por nombre parcial
                if sn.resolved_symbol.endswith(expected_suffix):
                    return method.method_id

        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _node_attrs(self, node: DfgNode) -> dict[str, Any]:
        """Convierte un DfgNode a atributos del nodo NetworkX."""
        return {
            "kind": node.kind.name,
            "label": node.label,
            "method_id": node.method_id,
            "line": node.line,
            "is_literal": node.is_literal,
            "dfg_node": node,  # Referencia directa para acceso rápido
        }


# ─────────────────────────────────────────────────────────────────────────────
#  ANALIZADOR DE TAINT SOBRE EL DFG
# ─────────────────────────────────────────────────────────────────────────────

class DfgTaintPropagator:
    """
    Propaga el taint a través del DFG.
    Este componente es la interfaz entre el DfgBuilder y el TaintAnalyzer.

    El TaintAnalyzer llama a este propagador para determinar qué nodos
    del DFG están tainted dado un conjunto de nodos source.
    """

    def propagate(
        self,
        method_dfg: MethodDfg,
        initial_tainted_ids: set[str],
        sanitizer_dfg_ids: set[str] | None = None,
    ) -> dict[str, str]:
        """
        Propaga el taint desde los nodos iniciales por el DFG.

        Args:
            method_dfg: El DFG del método a analizar.
            initial_tainted_ids: IDs de DfgNode inicialmente tainted.
            sanitizer_dfg_ids: IDs de nodos que sanitizan el taint.

        Returns:
            Dict {dfg_node_id: taint_label} de todos los nodos tainted.
        """
        if sanitizer_dfg_ids is None:
            sanitizer_dfg_ids = set()

        tainted: dict[str, str] = {}
        queue = list(initial_tainted_ids)

        # Marcar nodos iniciales como tainted
        for nid in initial_tainted_ids:
            tainted[nid] = "USER_INPUT"

        # BFS de propagación
        visited: set[str] = set(initial_tainted_ids)

        while queue:
            current_id = queue.pop(0)

            # Si llegamos a un sanitizador, el taint se detiene
            if current_id in sanitizer_dfg_ids:
                logger.debug("Taint bloqueado por sanitizador: %s", current_id[:12])
                continue

            for successor_id in method_dfg.graph.successors(current_id):
                if successor_id in visited:
                    continue

                edge_data = method_dfg.graph.edges[current_id, successor_id]
                edge_kind = edge_data.get("edge_kind", "flows_to")

                # Los sanitizadores en el camino bloquean el flujo
                if successor_id in sanitizer_dfg_ids:
                    continue

                # Propagar el taint
                tainted[successor_id] = tainted.get(current_id, "USER_INPUT")
                visited.add(successor_id)
                queue.append(successor_id)

        return tainted

    def get_tainted_sinks(
        self,
        method_dfg: MethodDfg,
        tainted_nodes: dict[str, str],
    ) -> list[tuple[DfgNode, str]]:
        """
        Retorna los nodos sink que están tainted.

        Returns:
            Lista de (DfgNode_sink, taint_label).
        """
        result = []
        for sink_dfg_id in method_dfg.sink_nodes:
            if sink_dfg_id in tainted_nodes:
                sink_node = method_dfg.nodes_by_id.get(sink_dfg_id)
                if sink_node:
                    result.append((sink_node, tainted_nodes[sink_dfg_id]))
        return result
