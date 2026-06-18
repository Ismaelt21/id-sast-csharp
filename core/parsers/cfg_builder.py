# =============================================================================
#  csharp-sast / core / parsers / cfg_builder.py
# =============================================================================
#
#  CONSTRUCTOR DEL CONTROL FLOW GRAPH (CFG)
#  ──────────────────────────────────────────
#  Construye el grafo CFG de NetworkX desde los datos exportados por Roslyn.
#
#  POR QUÉ NetworkX:
#    El engine Python usa NetworkX para todos sus grafos (CFG, DFG, call graph).
#    Los algoritmos de taint analysis (BFS, DFS, dominancia) operan sobre
#    DiGraph de NetworkX, lo que permite reutilizar la infraestructura del
#    engine py-sast existente.
#
#  QUÉ CONSTRUYE:
#    Para cada método con CFG en el ParsedCSharpModel:
#      • nx.DiGraph con nodos = CfgBlock.block_id
#      • Aristas tipadas (edge_kind como atributo)
#      • Atributos de nodo: líneas, node_ids de SemanticNodes,
#        tipo de bloque, branch condition
#      • Metadatos del grafo: method_id, entry, exits
#
#  ALGORITMOS ADICIONALES:
#    • Cálculo de dominadores (para detectar si un sink SIEMPRE es alcanzado)
#    • Detección de loops (bloques dentro de ciclos)
#    • Alcanzabilidad (¿puede el bloque X llegar al bloque Y?)
#    • Extracción de caminos (para generar traces en reportes)
#
#  RELACIÓN CON TAINT ANALYZER:
#    taint_analyzer.py usa el CfgGraph para determinar:
#      • Si un sink es DEFINITIVAMENTE alcanzable (vuln definitiva)
#        o POSIBLEMENTE alcanzable (vuln potencial)
#      • Si un sanitizador en el camino source→sink bloquea el flujo
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterator

try:
    import networkx as nx
except ImportError:
    raise ImportError(
        "NetworkX es requerido para el CFG builder. "
        "Instala con: pip install networkx"
    )

from .ast_importer import (
    CfgBlock,
    CfgEdge,
    CSharpSemanticNode,
    MethodCfg,
    ParsedCSharpModel,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  MODELO DEL CFG INTERNO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CfgGraph:
    """
    CFG de un método representado como nx.DiGraph.
    Envuelve el grafo NetworkX con métodos de análisis de alto nivel.
    """
    method_id: str
    method_name: str
    graph: nx.DiGraph
    entry_block_id: str
    exit_block_ids: list[str]

    # Metadatos de bloques (guardados aparte para acceso sin ir al grafo)
    blocks_meta: dict[str, CfgBlock] = field(default_factory=dict, repr=False)

    # Mapa block_id → [semantic_node_ids] en ese bloque
    block_to_nodes: dict[str, list[str]] = field(default_factory=dict, repr=False)

    # Mapa semantic_node_id → block_id (inverso)
    node_to_block: dict[str, str] = field(default_factory=dict, repr=False)

    # ── Análisis de alcanzabilidad ─────────────────────────────────────────

    def is_reachable(self, source_block_id: str, target_block_id: str) -> bool:
        """True si target es alcanzable desde source en el CFG."""
        if source_block_id == target_block_id:
            return True
        try:
            return nx.has_path(self.graph, source_block_id, target_block_id)
        except nx.NodeNotFound:
            return False

    def find_paths(
        self, source_block_id: str, target_block_id: str, max_paths: int = 5
    ) -> list[list[str]]:
        """
        Encuentra hasta max_paths caminos entre source y target.
        Los caminos se usan para generar traces de vulnerabilidades.
        """
        try:
            paths = list(nx.all_simple_paths(
                self.graph, source_block_id, target_block_id, cutoff=20
            ))
            return paths[:max_paths]
        except (nx.NodeNotFound, nx.NetworkXError):
            return []

    def blocks_on_all_paths(
        self, source_block_id: str, target_block_id: str
    ) -> set[str]:
        """
        Retorna bloques que están en TODOS los caminos de source a target.
        Un bloque en todos los caminos domina la ejecución del sink.
        Usado para determinar si un sanitizador SIEMPRE se ejecuta antes del sink.
        """
        paths = self.find_paths(source_block_id, target_block_id, max_paths=20)
        if not paths:
            return set()
        # Intersección de todos los caminos
        sets = [set(path) for path in paths]
        return set.intersection(*sets) - {source_block_id, target_block_id}

    def get_dominators(self) -> dict[str, set[str]]:
        """
        Calcula el conjunto dominador de cada bloque.
        Un bloque D domina B si todo camino desde entry hasta B pasa por D.
        """
        try:
            dom_tree = nx.immediate_dominators(self.graph, self.entry_block_id)
            # Expandir a conjuntos completos de dominadores
            dominators: dict[str, set[str]] = {}
            for node in self.graph.nodes:
                doms: set[str] = set()
                current = node
                while current != dom_tree.get(current, current):
                    parent = dom_tree[current]
                    doms.add(parent)
                    current = parent
                doms.add(node)
                dominators[node] = doms
            return dominators
        except Exception as exc:
            logger.debug("No se pudo calcular dominadores para %s: %s", self.method_name, exc)
            return {}

    def detect_loop_blocks(self) -> set[str]:
        """Retorna IDs de bloques que están dentro de ciclos."""
        try:
            # Un bloque está en un loop si está en un ciclo del grafo
            loops: set[str] = set()
            for cycle in nx.simple_cycles(self.graph):
                loops.update(cycle)
            return loops
        except Exception:
            return set()

    def get_exception_handler_blocks(self) -> set[str]:
        """Retorna IDs de bloques que son manejadores de excepciones (catch/finally)."""
        return {
            block_id
            for block_id, meta in self.blocks_meta.items()
            if meta.is_exception_handler
        }

    def blocks_with_sanitizer(
        self, sanitizer_node_ids: set[str]
    ) -> set[str]:
        """
        Retorna IDs de bloques que contienen nodos sanitizadores.
        Usado por el taint analyzer para verificar si el sanitizador
        bloquea el flujo taint.
        """
        result: set[str] = set()
        for block_id, node_ids in self.block_to_nodes.items():
            if any(nid in sanitizer_node_ids for nid in node_ids):
                result.add(block_id)
        return result

    def get_block_for_node(self, semantic_node_id: str) -> str | None:
        """Retorna el block_id que contiene el semantic_node dado."""
        return self.node_to_block.get(semantic_node_id)

    def successor_blocks(self, block_id: str) -> list[str]:
        """Retorna los bloques sucesores directos."""
        return list(self.graph.successors(block_id))

    def predecessor_blocks(self, block_id: str) -> list[str]:
        """Retorna los bloques predecesores directos."""
        return list(self.graph.predecessors(block_id))

    def topological_order(self) -> list[str]:
        """
        Retorna los bloques en orden topológico (para análisis de flujo de datos).
        Si hay ciclos (loops), usa un orden aproximado.
        """
        try:
            return list(nx.topological_sort(self.graph))
        except nx.NetworkXUnfeasible:
            # El CFG tiene ciclos (loops); usar BFS desde entry
            return list(nx.bfs_tree(self.graph, self.entry_block_id).nodes())

    def iter_blocks_with_edges(
        self,
    ) -> Iterator[tuple[str, str, str]]:
        """Itera (from_block_id, to_block_id, edge_kind)."""
        for u, v, data in self.graph.edges(data=True):
            yield u, v, data.get("edge_kind", "sequential")

    def __repr__(self) -> str:
        return (
            f"CfgGraph(method={self.method_name!r}, "
            f"blocks={self.graph.number_of_nodes()}, "
            f"edges={self.graph.number_of_edges()})"
        )


@dataclass
class ProjectCfgIndex:
    """
    Índice de todos los CFGs del proyecto.
    Punto de entrada para el taint analyzer y el DFG builder.
    """
    cfgs: dict[str, CfgGraph] = field(default_factory=dict)

    def get(self, method_id: str) -> CfgGraph | None:
        return self.cfgs.get(method_id)

    def __len__(self) -> int:
        return len(self.cfgs)

    def __iter__(self) -> Iterator[CfgGraph]:
        return iter(self.cfgs.values())


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTRUCTOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class CfgBuilder:
    """
    Construye los CfgGraph de NetworkX desde el ParsedCSharpModel.

    Uso:
        builder = CfgBuilder()
        cfg_index = builder.build(model)
        cfg = cfg_index.get(method_id)
        reachable = cfg.is_reachable(source_block, sink_block)
    """

    def build(self, model: ParsedCSharpModel) -> ProjectCfgIndex:
        """
        Construye el índice de CFGs para todos los métodos del proyecto.

        Args:
            model: El ParsedCSharpModel importado por AstImporter.

        Returns:
            ProjectCfgIndex con un CfgGraph por método analizado.
        """
        index = ProjectCfgIndex()
        total = len(model.method_cfgs)
        failed = 0

        for method_cfg in model.method_cfgs:
            try:
                cfg_graph = self._build_method_cfg(method_cfg, model)
                index.cfgs[method_cfg.method_id] = cfg_graph
            except Exception as exc:
                failed += 1
                logger.warning(
                    "No se pudo construir CFG para método %s: %s",
                    method_cfg.method_name,
                    exc,
                )

        logger.info(
            "CFG construido: %d/%d métodos exitosos, %d fallidos.",
            total - failed,
            total,
            failed,
        )
        return index

    def build_for_method(
        self,
        method_id: str,
        model: ParsedCSharpModel,
    ) -> CfgGraph | None:
        """Construye el CFG solo para un método específico."""
        method_cfg = model.cfgs_by_method_id.get(method_id)
        if not method_cfg:
            return None
        try:
            return self._build_method_cfg(method_cfg, model)
        except Exception as exc:
            logger.warning("No se pudo construir CFG para %s: %s", method_id, exc)
            return None

    # ─────────────────────────────────────────────────────────────────────────
    #  CONSTRUCCIÓN DEL GRAFO PARA UN MÉTODO
    # ─────────────────────────────────────────────────────────────────────────

    def _build_method_cfg(
        self, method_cfg: MethodCfg, model: ParsedCSharpModel
    ) -> CfgGraph:
        """Construye el nx.DiGraph para un método específico."""
        g = nx.DiGraph()
        g.graph["method_id"] = method_cfg.method_id
        g.graph["method_name"] = method_cfg.method_name

        blocks_meta: dict[str, CfgBlock] = {}
        block_to_nodes: dict[str, list[str]] = {}
        node_to_block: dict[str, str] = {}

        # ── 1. Añadir nodos (bloques básicos) ─────────────────────────────────
        for block in method_cfg.blocks:
            # Atributos del nodo en el grafo
            node_attrs = {
                "kind": block.kind,
                "line_start": block.line_start,
                "line_end": block.line_end,
                "node_ids": block.node_ids,
                "branch_condition": block.branch_condition,
                "is_exception_handler": block.is_exception_handler,
                "is_entry": block.block_id == method_cfg.entry_block_id,
                "is_exit": block.block_id in method_cfg.exit_block_ids,
            }
            g.add_node(block.block_id, **node_attrs)
            blocks_meta[block.block_id] = block
            block_to_nodes[block.block_id] = list(block.node_ids)

            # Construir el índice inverso (node_id → block_id)
            for nid in block.node_ids:
                node_to_block[nid] = block.block_id

        # ── 2. Añadir aristas ─────────────────────────────────────────────────
        for edge in method_cfg.edges:
            # Ignorar aristas a bloques que no existen en el grafo
            if edge.from_block_id not in g.nodes or edge.to_block_id not in g.nodes:
                logger.debug(
                    "Arista ignorada: %s → %s (bloque no existe)",
                    edge.from_block_id[:8],
                    edge.to_block_id[:8],
                )
                continue

            g.add_edge(
                edge.from_block_id,
                edge.to_block_id,
                edge_kind=edge.edge_kind,
                is_conditional=(edge.edge_kind in ("true_branch", "false_branch")),
                is_exception=(edge.edge_kind in ("exception", "throw")),
            )

        # ── 3. Asegurar que el entry block existe ─────────────────────────────
        entry = method_cfg.entry_block_id
        if entry not in g.nodes and g.nodes:
            # Fallback: usar el primer nodo como entry
            entry = next(iter(g.nodes))
            logger.debug(
                "Entry block no encontrado en método %s; usando %s como fallback.",
                method_cfg.method_name,
                entry[:8],
            )

        # ── 4. Enrichment: marcar bloques con sinks/sources ───────────────────
        self._mark_sink_blocks(g, block_to_nodes, model, method_cfg.method_id)

        return CfgGraph(
            method_id=method_cfg.method_id,
            method_name=method_cfg.method_name,
            graph=g,
            entry_block_id=entry,
            exit_block_ids=list(method_cfg.exit_block_ids),
            blocks_meta=blocks_meta,
            block_to_nodes=block_to_nodes,
            node_to_block=node_to_block,
        )

    def _mark_sink_blocks(
        self,
        g: nx.DiGraph,
        block_to_nodes: dict[str, list[str]],
        model: ParsedCSharpModel,
        method_id: str,
    ) -> None:
        """
        Añade atributos 'has_sink', 'has_source', 'has_sanitizer' a los bloques.
        Acelera las búsquedas del taint analyzer.
        """
        nodes_in_method = {n.node_id: n for n in model.nodes_by_method.get(method_id, [])}

        for block_id, node_ids in block_to_nodes.items():
            if block_id not in g.nodes:
                continue

            has_sink = False
            has_source = False
            has_sanitizer = False

            for nid in node_ids:
                node = nodes_in_method.get(nid)
                if node:
                    has_sink = has_sink or node.is_known_sink
                    has_source = has_source or node.is_known_source
                    has_sanitizer = has_sanitizer or node.is_known_sanitizer

            g.nodes[block_id]["has_sink"] = has_sink
            g.nodes[block_id]["has_source"] = has_source
            g.nodes[block_id]["has_sanitizer"] = has_sanitizer


# ─────────────────────────────────────────────────────────────────────────────
#  ANALIZADOR DE CAMINOS PARA REPORTES
# ─────────────────────────────────────────────────────────────────────────────

class CfgPathAnalyzer:
    """
    Extrae caminos de ejecución entre source y sink para los reportes.
    Usado por el vulnerability_classifier para generar el "trace" de la vuln.
    """

    def __init__(self, cfg: CfgGraph, model: ParsedCSharpModel) -> None:
        self._cfg = cfg
        self._model = model

    def get_taint_trace(
        self,
        source_node_id: str,
        sink_node_id: str,
    ) -> list[dict[str, Any]] | None:
        """
        Genera el trace de la vulnerabilidad desde el source hasta el sink.

        Returns:
            Lista de dicts con información de cada paso del trace:
            [{"block_id": ..., "line": ..., "semantic_nodes": [...]}]
            None si no existe camino.
        """
        source_block = self._cfg.get_block_for_node(source_node_id)
        sink_block = self._cfg.get_block_for_node(sink_node_id)

        if not source_block or not sink_block:
            return None

        paths = self._cfg.find_paths(source_block, sink_block, max_paths=1)
        if not paths:
            return None

        trace = []
        for block_id in paths[0]:
            block_meta = self._cfg.blocks_meta.get(block_id)
            if not block_meta:
                continue

            # Obtener los SemanticNodes del bloque
            node_ids = self._cfg.block_to_nodes.get(block_id, [])
            nodes_info = []
            for nid in node_ids:
                node = self._model.nodes_by_id.get(nid)
                if node:
                    nodes_info.append({
                        "node_id": nid,
                        "kind": node.kind,
                        "text": node.text,
                        "line": node.line,
                        "is_sink": node.is_known_sink,
                        "is_source": node.is_known_source,
                        "is_sanitizer": node.is_known_sanitizer,
                    })

            trace.append({
                "block_id": block_id,
                "kind": block_meta.kind,
                "line_start": block_meta.line_start,
                "line_end": block_meta.line_end,
                "semantic_nodes": nodes_info,
            })

        return trace

    def is_sanitized_on_all_paths(
        self,
        source_node_id: str,
        sink_node_id: str,
        sanitizer_node_ids: set[str],
    ) -> bool:
        """
        True si TODOS los caminos desde source hasta sink
        pasan por al menos un sanitizador.

        Esta es la verificación crítica que elimina falsos positivos:
        si el sanitizador está en todos los caminos, la vuln no existe.
        """
        source_block = self._cfg.get_block_for_node(source_node_id)
        sink_block = self._cfg.get_block_for_node(sink_node_id)

        if not source_block or not sink_block:
            return False

        sanitizer_blocks = self._cfg.blocks_with_sanitizer(sanitizer_node_ids)

        paths = self._cfg.find_paths(source_block, sink_block, max_paths=20)
        if not paths:
            return False

        # Verificar si cada camino pasa por al menos un sanitizador
        for path in paths:
            path_set = set(path)
            if not path_set & sanitizer_blocks:
                # Este camino no tiene sanitizador → no está sanitizado
                return False

        return True  # Todos los caminos tienen sanitizador