# =============================================================================
#  csharp-sast / core / graph / csharp_graph_model.py
# =============================================================================
#
#  MODELO DE GRAFO UNIFICADO PARA C#
#  ────────────────────────────────────
#  Define el modelo de grafo centralizado que conecta:
#    • CFG  (Control Flow Graph)   — de cfg_builder.py
#    • DFG  (Data Flow Graph)      — de dfg_builder.py
#    • CGR  (Call Graph)           — construido aquí desde el ParsedCSharpModel
#    • TFG  (Taint Flow Graph)     — generado por taint_propagator.py
#
#  POR QUÉ UN MODELO UNIFICADO:
#    El taint_analyzer necesita navegar los 3 grafos simultáneamente:
#      1. DFG:  ¿fluyen datos desde source hasta sink?
#      2. CFG:  ¿es ese flujo definitivamente alcanzable?
#      3. CGR:  ¿el dato cruza límites de método?
#    Un modelo unificado evita referencias cruzadas dispersas
#    y facilita el análisis multi-grafo.
#
#  RELACIÓN CON py-sast:
#    Extiende el concepto de graph_model.py de py-sast con nodos y
#    aristas específicos de C# (async/await, LINQ, generics, extension methods).
#
#  NODOS DEL GRAFO UNIFICADO:
#    CSharpNode             — nodo base con metadata C#
#    ├── SemanticCallNode   — invocación de método (sink o call)
#    ├── ParameterNode      — parámetro de método (source potencial)
#    ├── AssignmentNode     — asignación de variable
#    ├── ReturnNode         — retorno de método
#    ├── ControlNode        — nodo de control de flujo (if, while, switch)
#    ├── AwaitNode          — await de Task/ValueTask
#    └── LambdaNode         — lambda / closure
#
#  ARISTAS DEL GRAFO UNIFICADO:
#    CSharpEdge             — arista base
#    ├── DataFlowEdge       — flujo de datos (taint)
#    ├── ControlFlowEdge    — flujo de control (CFG)
#    ├── CallEdge           — llamada de método (call graph)
#    └── AliasEdge          — alias de variable
#
# =============================================================================

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Iterator

try:
    import networkx as nx
except ImportError:
    raise ImportError("NetworkX requerido: pip install networkx")

from core.parsers.ast_importer import (
    CSharpSemanticNode,
    ClassInfo,
    MethodInfo,
    ParsedCSharpModel,
)
from core.parsers.cfg_builder import CfgGraph, ProjectCfgIndex
from core.parsers.dfg_builder import DfgNode, DfgNodeKind, MethodDfg, ProjectDfgIndex


# ─────────────────────────────────────────────────────────────────────────────
#  ENUMS DEL MODELO DE GRAFO
# ─────────────────────────────────────────────────────────────────────────────

class NodeKind(Enum):
    """Tipos de nodo en el grafo unificado C#."""
    # Nodos de datos
    PARAMETER          = auto()   # Parámetro de método
    ASSIGNMENT         = auto()   # Asignación de variable local
    RETURN_VALUE       = auto()   # Valor de retorno
    FIELD_ACCESS       = auto()   # Acceso a campo/propiedad

    # Nodos de invocación
    METHOD_CALL        = auto()   # Llamada a método externo
    OBJECT_CREATION    = auto()   # new T(...)
    DELEGATE_CALL      = auto()   # Invocación de delegate / Func<T>
    EXTENSION_CALL     = auto()   # Llamada a extension method

    # Nodos de control
    CONDITION          = auto()   # Condición de if/while/switch
    LOOP_HEADER        = auto()   # Cabecera de loop (for, while, foreach)
    EXCEPTION_HANDLER  = auto()   # catch / finally

    # Nodos C#-específicos
    AWAIT_EXPR         = auto()   # await Task<T>
    LAMBDA_CAPTURE     = auto()   # Closure / lambda que captura variables
    LINQ_EXPRESSION    = auto()   # Expresión LINQ (.Where, .Select, .Any)
    STRING_INTERPOLATION = auto() # $"..."
    STRING_CONCAT      = auto()   # "..." + variable
    COLLECTION_ITEM    = auto()   # Elemento añadido a una colección

    # Nodos semánticos clasificados
    KNOWN_SOURCE       = auto()   # Source conocida (HttpRequest.Query, etc.)
    KNOWN_SINK         = auto()   # Sink conocido (SqlCommand, etc.)
    KNOWN_SANITIZER    = auto()   # Sanitizador conocido (HtmlEncoder, etc.)


class EdgeKind(Enum):
    """Tipos de arista en el grafo unificado C#."""
    # Data Flow
    FLOWS_TO        = "flows_to"        # Dato fluye directamente
    ALIASES         = "aliases"         # Dos variables son el mismo dato
    ASSIGNED_TO     = "assigned_to"     # Dato se asigna a esta variable
    RETURNED_BY     = "returned_by"     # Dato retorna de este método
    CAPTURED_BY     = "captured_by"     # Variable capturada por lambda

    # Control Flow
    SEQUENTIAL      = "sequential"      # Flujo secuencial
    TRUE_BRANCH     = "true_branch"     # Rama verdadera (if/while)
    FALSE_BRANCH    = "false_branch"    # Rama falsa
    EXCEPTION       = "exception"       # Flujo de excepción
    RETURN          = "return"          # Retorno de método

    # Call Graph
    CALLS           = "calls"           # A llama a B
    CALLED_BY       = "called_by"       # B es llamado por A
    OVERRIDES       = "overrides"       # A sobreescribe B (herencia)

    # Taint
    TAINTS          = "taints"          # Dato tainted fluye a este nodo
    SANITIZES       = "sanitizes"       # Nodo sanitiza el taint


class TaintState(Enum):
    """Estado de taint de un nodo en el grafo."""
    CLEAN           = "clean"         # No tainted
    TAINTED         = "tainted"       # Contaminado con datos del usuario
    PARTIALLY_TAINTED = "partial"     # Tainted en algunos caminos
    SANITIZED       = "sanitized"     # Fue tainted pero sanitizado
    UNKNOWN         = "unknown"       # Estado no determinado


# ─────────────────────────────────────────────────────────────────────────────
#  NODOS DEL GRAFO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CSharpNode:
    """
    Nodo base del grafo unificado C#.
    Todos los tipos de nodo heredan de esta clase.
    """
    node_id:        str
    kind:           NodeKind
    label:          str                    # Descripción legible
    file:           str
    line:           int
    column:         int = 0
    method_id:      str | None = None      # Método contenedor
    class_name:     str | None = None      # Clase contenedora

    # Estado de taint (actualizado por taint_propagator)
    taint_state:    TaintState = TaintState.UNKNOWN
    taint_label:    str | None = None      # "USER_INPUT", "EXTERNAL_INPUT", etc.
    taint_origin:   str | None = None      # node_id del source original

    # Metadata C#-específica
    resolved_symbol: str | None = None    # Símbolo Roslyn resuelto
    resolved_type:   str | None = None    # Tipo .NET del nodo
    is_async:        bool = False          # Nodo en contexto async/await
    is_in_loop:      bool = False          # Nodo dentro de un loop
    is_in_try:       bool = False          # Nodo dentro de try/catch

    # Atributos adicionales (flexibles)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def is_known_sink(self) -> bool:
        return self.kind == NodeKind.KNOWN_SINK

    @property
    def is_known_source(self) -> bool:
        return self.kind == NodeKind.KNOWN_SOURCE

    @property
    def is_known_sanitizer(self) -> bool:
        return self.kind == NodeKind.KNOWN_SANITIZER

    @property
    def is_tainted(self) -> bool:
        return self.taint_state in (
            TaintState.TAINTED, TaintState.PARTIALLY_TAINTED
        )

    def mark_tainted(self, label: str, origin: str) -> None:
        """Marca el nodo como tainted con el label y origen dados."""
        self.taint_state  = TaintState.TAINTED
        self.taint_label  = label
        self.taint_origin = origin

    def mark_sanitized(self) -> None:
        """Marca el nodo como sanitizado (el taint fue interrumpido)."""
        self.taint_state = TaintState.SANITIZED

    def mark_clean(self) -> None:
        self.taint_state = TaintState.CLEAN

    def to_dict(self) -> dict[str, Any]:
        """Serializa el nodo a dict para exportación."""
        return {
            "node_id":        self.node_id,
            "kind":           self.kind.name,
            "label":          self.label,
            "file":           self.file,
            "line":           self.line,
            "column":         self.column,
            "method_id":      self.method_id,
            "class_name":     self.class_name,
            "taint_state":    self.taint_state.value,
            "taint_label":    self.taint_label,
            "taint_origin":   self.taint_origin,
            "resolved_symbol": self.resolved_symbol,
            "resolved_type":  self.resolved_type,
            "is_async":       self.is_async,
            "is_in_loop":     self.is_in_loop,
            "is_in_try":      self.is_in_try,
            "attributes":     self.attributes,
        }

    def __repr__(self) -> str:
        taint_info = f", taint={self.taint_state.value}" if self.is_tainted else ""
        return (
            f"CSharpNode({self.kind.name}:{self.label[:40]!r}"
            f"@L{self.line}{taint_info})"
        )


@dataclass
class CSharpEdge:
    """
    Arista del grafo unificado C#.
    Conecta dos CSharpNode con semántica de flujo de datos, control o llamada.
    """
    edge_id:       str
    from_node_id:  str
    to_node_id:    str
    kind:          EdgeKind
    label:         str = ""

    # Metadata específica del tipo de arista
    taint_label:       str | None = None    # Si carries taint
    confidence:        float = 1.0          # Confianza del flujo
    is_conditional:    bool = False         # Flujo condicional (puede no ocurrir)
    argument_position: int | None = None    # Posición del argumento en llamadas
    via_alias:         str | None = None    # Nombre de la variable alias

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id":          self.edge_id,
            "from_node_id":     self.from_node_id,
            "to_node_id":       self.to_node_id,
            "kind":             self.kind.value,
            "label":            self.label,
            "taint_label":      self.taint_label,
            "confidence":       self.confidence,
            "is_conditional":   self.is_conditional,
            "argument_position": self.argument_position,
            "via_alias":        self.via_alias,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  GRAFO UNIFICADO C#
# ─────────────────────────────────────────────────────────────────────────────

class CSharpUnifiedGraph:
    """
    Grafo unificado que combina CFG, DFG y Call Graph de un proyecto C#.

    Estructura interna:
      • nx.DiGraph como backbone (para algoritmos de grafo)
      • CSharpNode como atributos de nodo ('node_data')
      • CSharpEdge como atributos de arista ('edge_data')

    El grafo es navegable en ambas direcciones (predecessores y sucesores).
    """

    def __init__(self, project_name: str = "csharp_project") -> None:
        self.project_name = project_name
        self._graph: nx.DiGraph = nx.DiGraph(project=project_name)
        self._nodes: dict[str, CSharpNode] = {}
        self._edges: dict[str, CSharpEdge] = {}

        # Índices especializados (construidos durante la inserción)
        self._nodes_by_kind:      dict[NodeKind, list[str]] = {}
        self._nodes_by_method:    dict[str, list[str]] = {}
        self._nodes_by_file:      dict[str, list[str]] = {}
        self._source_node_ids:    set[str] = set()
        self._sink_node_ids:      set[str] = set()
        self._sanitizer_node_ids: set[str] = set()

    # ─────────────────────────────────────────────────────────────────────────
    #  INSERCIÓN DE NODOS Y ARISTAS
    # ─────────────────────────────────────────────────────────────────────────

    def add_node(self, node: CSharpNode) -> str:
        """
        Añade un nodo al grafo.
        Retorna el node_id asignado.
        """
        self._nodes[node.node_id] = node
        self._graph.add_node(node.node_id, node_data=node)

        # Índices
        self._nodes_by_kind.setdefault(node.kind, []).append(node.node_id)
        if node.method_id:
            self._nodes_by_method.setdefault(node.method_id, []).append(node.node_id)
        if node.file:
            self._nodes_by_file.setdefault(node.file, []).append(node.node_id)

        # Índices especializados
        if node.kind == NodeKind.KNOWN_SOURCE:
            self._source_node_ids.add(node.node_id)
        elif node.kind == NodeKind.KNOWN_SINK:
            self._sink_node_ids.add(node.node_id)
        elif node.kind == NodeKind.KNOWN_SANITIZER:
            self._sanitizer_node_ids.add(node.node_id)

        return node.node_id

    def add_edge(self, edge: CSharpEdge) -> str:
        """
        Añade una arista al grafo.
        Retorna el edge_id asignado.
        Ignora aristas con nodos inexistentes.
        """
        if (edge.from_node_id not in self._nodes
                or edge.to_node_id not in self._nodes):
            return ""

        self._edges[edge.edge_id] = edge
        self._graph.add_edge(
            edge.from_node_id,
            edge.to_node_id,
            edge_data=edge,
            kind=edge.kind.value,
        )
        return edge.edge_id

    def get_node(self, node_id: str) -> CSharpNode | None:
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> CSharpEdge | None:
        return self._edges.get(edge_id)

    # ─────────────────────────────────────────────────────────────────────────
    #  ACCESORES POR TIPO
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def source_nodes(self) -> list[CSharpNode]:
        return [self._nodes[nid] for nid in self._source_node_ids
                if nid in self._nodes]

    @property
    def sink_nodes(self) -> list[CSharpNode]:
        return [self._nodes[nid] for nid in self._sink_node_ids
                if nid in self._nodes]

    @property
    def sanitizer_nodes(self) -> list[CSharpNode]:
        return [self._nodes[nid] for nid in self._sanitizer_node_ids
                if nid in self._nodes]

    @property
    def tainted_nodes(self) -> list[CSharpNode]:
        return [n for n in self._nodes.values() if n.is_tainted]

    @property
    def tainted_sinks(self) -> list[CSharpNode]:
        return [
            n for n in self.sink_nodes
            if n.is_tainted
        ]

    def get_nodes_by_kind(self, kind: NodeKind) -> list[CSharpNode]:
        ids = self._nodes_by_kind.get(kind, [])
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def get_nodes_in_method(self, method_id: str) -> list[CSharpNode]:
        ids = self._nodes_by_method.get(method_id, [])
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def get_nodes_in_file(self, file_path: str) -> list[CSharpNode]:
        ids = self._nodes_by_file.get(file_path, [])
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    # ─────────────────────────────────────────────────────────────────────────
    #  NAVEGACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def successors(self, node_id: str) -> list[CSharpNode]:
        """Nodos sucesores directos."""
        return [
            self._nodes[nid]
            for nid in self._graph.successors(node_id)
            if nid in self._nodes
        ]

    def predecessors(self, node_id: str) -> list[CSharpNode]:
        """Nodos predecesores directos."""
        return [
            self._nodes[nid]
            for nid in self._graph.predecessors(node_id)
            if nid in self._nodes
        ]

    def get_outgoing_edges(self, node_id: str) -> list[CSharpEdge]:
        """Aristas salientes de un nodo."""
        result = []
        for _, to_id, data in self._graph.out_edges(node_id, data=True):
            edge = data.get("edge_data")
            if edge:
                result.append(edge)
        return result

    def get_incoming_edges(self, node_id: str) -> list[CSharpEdge]:
        """Aristas entrantes a un nodo."""
        result = []
        for from_id, _, data in self._graph.in_edges(node_id, data=True):
            edge = data.get("edge_data")
            if edge:
                result.append(edge)
        return result

    def get_data_flow_successors(self, node_id: str) -> list[CSharpNode]:
        """Sucesores conectados por aristas de flujo de datos."""
        data_flow_kinds = {
            EdgeKind.FLOWS_TO.value,
            EdgeKind.ALIASES.value,
            EdgeKind.ASSIGNED_TO.value,
            EdgeKind.CAPTURED_BY.value,
            EdgeKind.TAINTS.value,
        }
        result = []
        for edge in self.get_outgoing_edges(node_id):
            if edge.kind.value in data_flow_kinds:
                node = self._nodes.get(edge.to_node_id)
                if node:
                    result.append(node)
        return result

    # ─────────────────────────────────────────────────────────────────────────
    #  ALGORITMOS DE GRAFO
    # ─────────────────────────────────────────────────────────────────────────

    def is_reachable(self, from_node_id: str, to_node_id: str) -> bool:
        """True si to_node es alcanzable desde from_node."""
        try:
            return nx.has_path(self._graph, from_node_id, to_node_id)
        except nx.NodeNotFound:
            return False

    def find_paths(
        self,
        from_node_id: str,
        to_node_id: str,
        max_paths: int = 5,
        cutoff: int = 20,
    ) -> list[list[CSharpNode]]:
        """
        Encuentra caminos entre dos nodos.
        Retorna listas de CSharpNode en orden de recorrido.
        """
        try:
            raw_paths = list(nx.all_simple_paths(
                self._graph, from_node_id, to_node_id, cutoff=cutoff
            ))[:max_paths]
        except (nx.NodeNotFound, nx.NetworkXError):
            return []

        result = []
        for path in raw_paths:
            node_path = [
                self._nodes[nid] for nid in path
                if nid in self._nodes
            ]
            result.append(node_path)
        return result

    def find_taint_paths(
        self,
        source_node_id: str,
        sink_node_id: str,
        max_paths: int = 3,
    ) -> list[list[CSharpNode]]:
        """
        Encuentra caminos de taint entre source y sink,
        filtrando por aristas de tipo FLOWS_TO / TAINTS.
        """
        taint_subgraph = nx.DiGraph()

        for from_id, to_id, data in self._graph.edges(data=True):
            edge: CSharpEdge | None = data.get("edge_data")
            if edge and edge.kind in (
                EdgeKind.FLOWS_TO,
                EdgeKind.ALIASES,
                EdgeKind.ASSIGNED_TO,
                EdgeKind.CAPTURED_BY,
                EdgeKind.TAINTS,
                EdgeKind.RETURNED_BY,
            ):
                taint_subgraph.add_edge(from_id, to_id)

        try:
            raw_paths = list(nx.all_simple_paths(
                taint_subgraph, source_node_id, sink_node_id, cutoff=15
            ))[:max_paths]
        except (nx.NodeNotFound, nx.NetworkXError):
            return []

        return [
            [self._nodes[nid] for nid in path if nid in self._nodes]
            for path in raw_paths
        ]

    def get_sanitizers_between(
        self,
        source_node_id: str,
        sink_node_id: str,
    ) -> list[CSharpNode]:
        """
        Retorna sanitizadores en los caminos de source a sink.
        Usado por el taint_propagator para verificar si el taint está bloqueado.
        """
        paths = self.find_taint_paths(source_node_id, sink_node_id, max_paths=10)
        sanitizers = set()

        for path in paths:
            for node in path[1:-1]:  # Excluir source y sink
                if node.is_known_sanitizer:
                    sanitizers.add(node.node_id)

        return [self._nodes[nid] for nid in sanitizers if nid in self._nodes]

    def detect_loops(self) -> set[str]:
        """Retorna node_ids que están dentro de ciclos (loops)."""
        loop_nodes: set[str] = set()
        try:
            for cycle in nx.simple_cycles(self._graph):
                loop_nodes.update(cycle)
        except Exception:
            pass
        return loop_nodes

    # ─────────────────────────────────────────────────────────────────────────
    #  ESTADÍSTICAS
    # ─────────────────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, int]:
        kind_counts = {}
        for kind in NodeKind:
            count = len(self._nodes_by_kind.get(kind, []))
            if count > 0:
                kind_counts[kind.name] = count

        return {
            "total_nodes":   len(self._nodes),
            "total_edges":   len(self._edges),
            "source_nodes":  len(self._source_node_ids),
            "sink_nodes":    len(self._sink_node_ids),
            "sanitizers":    len(self._sanitizer_node_ids),
            "tainted_nodes": len(self.tainted_nodes),
            **kind_counts,
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"CSharpUnifiedGraph("
            f"nodes={s['total_nodes']}, "
            f"edges={s['total_edges']}, "
            f"sources={s['source_nodes']}, "
            f"sinks={s['sink_nodes']}, "
            f"tainted={s['tainted_nodes']})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  BUILDER DEL GRAFO UNIFICADO
# ─────────────────────────────────────────────────────────────────────────────

class CSharpGraphBuilder:
    """
    Construye el CSharpUnifiedGraph desde el ParsedCSharpModel,
    ProjectCfgIndex y ProjectDfgIndex.

    Fusiona los 3 grafos en una representación unificada navegable
    por el taint_propagator y el taint_analyzer.
    """

    def __init__(self) -> None:
        self._node_counter = 0

    def build(
        self,
        model:     ParsedCSharpModel,
        cfg_index: ProjectCfgIndex,
        dfg_index: ProjectDfgIndex,
    ) -> CSharpUnifiedGraph:
        """
        Construye el grafo unificado completo.

        Pasos:
          1. Crear nodos desde los SemanticNodes del modelo
          2. Conectar nodos de parámetros y asignaciones
          3. Añadir aristas de CFG (control flow)
          4. Añadir aristas de DFG (data flow)
          5. Añadir aristas del call graph (inter-procedural)
          6. Marcar nodos en loops
        """
        graph = CSharpUnifiedGraph(project_name="csharp-sast")

        # Mapas de traducción: id original → CSharpNode.node_id
        semantic_id_map: dict[str, str] = {}    # semantic_node_id → graph_node_id
        param_id_map:    dict[str, str] = {}    # "method_id::param_name" → graph_node_id
        asgn_id_map:     dict[str, str] = {}    # assignment_id → graph_node_id

        # ── 1. Nodos desde SemanticNodes ──────────────────────────────────────
        for sn in model.semantic_nodes:
            kind = self._classify_node_kind(sn)
            node = CSharpNode(
                node_id=self._new_id(),
                kind=kind,
                label=sn.text[:80],
                file=sn.file,
                line=sn.line,
                column=sn.column,
                method_id=sn.containing_method_id,
                class_name=self._get_class_name(sn, model),
                resolved_symbol=sn.resolved_symbol,
                resolved_type=sn.resolved_type,
                is_async=sn.is_async_call,
                is_in_try=sn.is_in_try_block,
            )
            graph.add_node(node)
            semantic_id_map[sn.node_id] = node.node_id

        # ── 2. Nodos de parámetros ────────────────────────────────────────────
        for cls in model.classes:
            for method in cls.methods:
                for param in method.parameters:
                    key = f"{method.method_id}::{param.name}"
                    node = CSharpNode(
                        node_id=self._new_id(),
                        kind=NodeKind.PARAMETER,
                        label=f"{method.name}.{param.name}:{param.resolved_type.split('.')[-1]}",
                        file=method.file,
                        line=method.line_start,
                        method_id=method.method_id,
                        class_name=cls.name,
                        resolved_type=param.resolved_type,
                    )
                    graph.add_node(node)
                    param_id_map[key] = node.node_id

        # ── 3. Nodos de asignaciones ──────────────────────────────────────────
        for asgn in model.assignments:
            if asgn.is_literal:
                continue
            kind = (
                NodeKind.STRING_INTERPOLATION
                if "interpolated" in asgn.target_name
                else NodeKind.STRING_CONCAT
                if "concat" in asgn.target_name
                else NodeKind.COLLECTION_ITEM
                if "collection" in asgn.target_name
                else NodeKind.LAMBDA_CAPTURE
                if "lambda" in asgn.target_name
                else NodeKind.ASSIGNMENT
            )
            method = model.methods_by_id.get(asgn.containing_method_id)
            node = CSharpNode(
                node_id=self._new_id(),
                kind=kind,
                label=f"{asgn.target_name} = {asgn.source_text[:40]}",
                file=method.file if method else "",
                line=asgn.line,
                method_id=asgn.containing_method_id,
            )
            graph.add_node(node)
            asgn_id_map[asgn.assignment_id] = node.node_id

        # ── 4. Aristas de Data Flow (desde DFG) ───────────────────────────────
        self._add_dfg_edges(
            graph, model, dfg_index,
            semantic_id_map, param_id_map, asgn_id_map,
        )

        # ── 5. Aristas de Call Graph ───────────────────────────────────────────
        self._add_call_graph_edges(graph, model, semantic_id_map)

        # ── 6. Marcar nodos en loops (desde CFG) ─────────────────────────────
        self._mark_loop_nodes(graph, model, cfg_index, semantic_id_map)

        return graph

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS DE CONSTRUCCIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _classify_node_kind(self, sn: CSharpSemanticNode) -> NodeKind:
        """Determina el NodeKind desde la clasificación del SemanticNode."""
        if sn.is_known_sink:
            return NodeKind.KNOWN_SINK
        if sn.is_known_source:
            return NodeKind.KNOWN_SOURCE
        if sn.is_known_sanitizer:
            return NodeKind.KNOWN_SANITIZER
        if sn.kind == "InvocationExpression":
            if sn.is_async_call:
                return NodeKind.AWAIT_EXPR
            if sn.resolved_symbol and "Linq" in sn.resolved_symbol:
                return NodeKind.LINQ_EXPRESSION
            return NodeKind.METHOD_CALL
        if sn.kind == "ObjectCreationExpression":
            return NodeKind.OBJECT_CREATION
        if sn.kind == "AssignmentExpression":
            return NodeKind.ASSIGNMENT
        if sn.kind == "ReturnStatement":
            return NodeKind.RETURN_VALUE
        return NodeKind.METHOD_CALL

    def _get_class_name(
        self,
        sn: CSharpSemanticNode,
        model: ParsedCSharpModel,
    ) -> str | None:
        if not sn.containing_method_id:
            return None
        method = model.methods_by_id.get(sn.containing_method_id)
        if not method:
            return None
        cls = model.classes_by_id.get(method.containing_class_id)
        return cls.name if cls else None

    def _add_dfg_edges(
        self,
        graph: CSharpUnifiedGraph,
        model: ParsedCSharpModel,
        dfg_index: ProjectDfgIndex,
        semantic_id_map: dict[str, str],
        param_id_map:    dict[str, str],
        asgn_id_map:     dict[str, str],
    ) -> None:
        """Añade aristas de flujo de datos desde el DFG."""
        for method_dfg in dfg_index:
            for from_dfg_id, to_dfg_id, data in method_dfg.graph.edges(data=True):
                edge_kind_str = data.get("edge_kind", "flows_to")

                # Resolver los IDs del DFG a IDs del grafo unificado
                from_graph_id = self._resolve_dfg_id(
                    from_dfg_id, method_dfg, semantic_id_map, param_id_map
                )
                to_graph_id = self._resolve_dfg_id(
                    to_dfg_id, method_dfg, semantic_id_map, param_id_map
                )

                if not from_graph_id or not to_graph_id:
                    continue

                edge_kind = self._map_dfg_edge_kind(edge_kind_str)
                edge = CSharpEdge(
                    edge_id=self._new_id(),
                    from_node_id=from_graph_id,
                    to_node_id=to_graph_id,
                    kind=edge_kind,
                    label=edge_kind_str,
                    argument_position=data.get("arg_position"),
                    via_alias=data.get("via_alias"),
                    is_conditional=data.get("is_conditional", False),
                )
                graph.add_edge(edge)

    def _resolve_dfg_id(
        self,
        dfg_node_id: str,
        method_dfg: MethodDfg,
        semantic_id_map: dict[str, str],
        param_id_map:    dict[str, str],
    ) -> str | None:
        """Convierte un DFG node_id al node_id del grafo unificado."""
        dfg_node = method_dfg.nodes_by_id.get(dfg_node_id)
        if not dfg_node:
            return None

        if dfg_node.kind == DfgNodeKind.SEMANTIC_NODE and dfg_node.semantic_node:
            return semantic_id_map.get(dfg_node.semantic_node.node_id)

        if dfg_node.kind == DfgNodeKind.PARAMETER and dfg_node.parameter_name:
            key = f"{method_dfg.method_id}::{dfg_node.parameter_name}"
            return param_id_map.get(key)

        return None

    def _map_dfg_edge_kind(self, edge_kind_str: str) -> EdgeKind:
        return {
            "flows_to":    EdgeKind.FLOWS_TO,
            "aliases":     EdgeKind.ALIASES,
            "assigned_to": EdgeKind.ASSIGNED_TO,
            "returned_by": EdgeKind.RETURNED_BY,
            "captured_by": EdgeKind.CAPTURED_BY,
        }.get(edge_kind_str, EdgeKind.FLOWS_TO)

    def _add_call_graph_edges(
        self,
        graph: CSharpUnifiedGraph,
        model: ParsedCSharpModel,
        semantic_id_map: dict[str, str],
    ) -> None:
        """Añade aristas del call graph inter-procedural."""
        # Mapa: method_name → nodo de retorno
        method_nodes: dict[str, list[str]] = {}

        for sn in model.semantic_nodes:
            if sn.kind != "InvocationExpression" or not sn.resolved_symbol:
                continue

            caller_graph_id = semantic_id_map.get(sn.node_id)
            if not caller_graph_id:
                continue

            # Buscar si la invocación es a un método interno del proyecto
            for cls in model.classes:
                for method in cls.methods:
                    if method.name in sn.resolved_symbol:
                        # Crear arista CALLS
                        for return_flow in model.return_flows:
                            if return_flow.method_id == method.method_id:
                                for ret_node_id in return_flow.returned_node_ids:
                                    ret_graph_id = semantic_id_map.get(ret_node_id)
                                    if ret_graph_id:
                                        edge = CSharpEdge(
                                            edge_id=self._new_id(),
                                            from_node_id=ret_graph_id,
                                            to_node_id=caller_graph_id,
                                            kind=EdgeKind.RETURNED_BY,
                                            label=f"{method.name}() → caller",
                                            confidence=0.85,
                                        )
                                        graph.add_edge(edge)

    def _mark_loop_nodes(
        self,
        graph: CSharpUnifiedGraph,
        model: ParsedCSharpModel,
        cfg_index: ProjectCfgIndex,
        semantic_id_map: dict[str, str],
    ) -> None:
        """Marca nodos del grafo que están dentro de loops usando el CFG."""
        for method_cfg in cfg_index:
            loop_blocks = method_cfg.detect_loop_blocks()
            if not loop_blocks:
                continue

            loop_node_ids: set[str] = set()
            for block_id in loop_blocks:
                block_node_ids = method_cfg.block_to_nodes.get(block_id, [])
                loop_node_ids.update(block_node_ids)

            for semantic_node_id in loop_node_ids:
                graph_node_id = semantic_id_map.get(semantic_node_id)
                if graph_node_id:
                    node = graph.get_node(graph_node_id)
                    if node:
                        node.is_in_loop = True

    def _new_id(self) -> str:
        self._node_counter += 1
        return f"gn-{self._node_counter:06d}"