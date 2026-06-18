# =============================================================================
#  csharp-sast / core / graph / graph_serializer.py
# =============================================================================
#
#  SERIALIZADOR DEL GRAFO UNIFICADO C#
#  ──────────────────────────────────────
#  Convierte el CSharpUnifiedGraph a/desde formatos de intercambio:
#    • JSON       — para persistencia en MongoDB y reportes
#    • dict       — para el VulnerabilityClassifier y SemanticAnalyzer
#    • GraphML    — estándar de grafos para herramientas externas (Gephi, yEd)
#    • DOT/Graphviz — visualización del grafo de taint
#
#  RESPONSABILIDADES:
#    1. Serializar nodos, aristas y metadatos del grafo a formatos portables
#    2. Deserializar grafos guardados en MongoDB para análisis histórico
#    3. Generar subgrafos de taint para reportes (solo source→sink paths)
#    4. Exportar snapshots del grafo antes/después del taint propagation
#    5. Serializar el grafo de forma incremental (por método o por archivo)
#
#  DISEÑO:
#    • No hay dependencias circulares: el serializer importa el modelo
#      pero el modelo NO importa el serializer
#    • El formato JSON es human-readable con snake_case
#    • El campo "schema_version" permite migración de grafos históricos
#    • Los nodos tainted se marcan explícitamente para query eficiente en MongoDB
#
# =============================================================================

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.graph.csharp_graph_model import (
    CSharpEdge,
    CSharpNode,
    CSharpUnifiedGraph,
    EdgeKind,
    NodeKind,
    TaintState,
)
from core.parsers.ast_importer import ParsedCSharpModel

logger = logging.getLogger(__name__)

# Versión del schema de serialización — incrementar al cambiar la estructura
GRAPH_SCHEMA_VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
#  FORMATOS DE SERIALIZACIÓN
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SerializedGraph:
    """
    Representación serializable del CSharpUnifiedGraph.
    Se puede convertir a JSON, dict o guardarse en MongoDB directamente.
    """
    schema_version:   str
    project_name:     str
    analysis_id:      str | None
    serialized_at:    str
    stats:            dict[str, int]

    # Nodos y aristas
    nodes:  list[dict[str, Any]]
    edges:  list[dict[str, Any]]

    # Índices de taint (para MongoDB queries eficientes)
    source_node_ids:    list[str]
    sink_node_ids:      list[str]
    sanitizer_node_ids: list[str]
    tainted_node_ids:   list[str]
    tainted_sink_ids:   list[str]

    # Metadatos del análisis
    framework:          str | None = None
    files_analyzed:     list[str] = None   # type: ignore[assignment]
    language_version:   str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "schema_version":    self.schema_version,
            "project_name":      self.project_name,
            "analysis_id":       self.analysis_id,
            "serialized_at":     self.serialized_at,
            "stats":             self.stats,
            "nodes":             self.nodes,
            "edges":             self.edges,
            "source_node_ids":   self.source_node_ids,
            "sink_node_ids":     self.sink_node_ids,
            "sanitizer_node_ids": self.sanitizer_node_ids,
            "tainted_node_ids":  self.tainted_node_ids,
            "tainted_sink_ids":  self.tainted_sink_ids,
            "framework":         self.framework,
            "files_analyzed":    self.files_analyzed or [],
            "language_version":  self.language_version,
        }
        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# ─────────────────────────────────────────────────────────────────────────────
#  SERIALIZADOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class GraphSerializer:
    """
    Serializa y deserializa el CSharpUnifiedGraph.

    Uso:
        serializer = GraphSerializer()

        # Serializar completo
        serialized = serializer.serialize(graph, model)
        json_str   = serialized.to_json()

        # Serializar solo subgrafo de taint
        taint_dict = serializer.serialize_taint_subgraph(graph)

        # Guardar a archivo
        serializer.save_to_file(graph, model, Path("output/graph.json"))

        # Exportar a DOT para visualización
        dot_str = serializer.to_dot(graph, highlight_taint=True)
    """

    # ─────────────────────────────────────────────────────────────────────────
    #  SERIALIZACIÓN COMPLETA
    # ─────────────────────────────────────────────────────────────────────────

    def serialize(
        self,
        graph:       CSharpUnifiedGraph,
        model:       ParsedCSharpModel | None = None,
        analysis_id: str | None = None,
    ) -> SerializedGraph:
        """
        Serializa el grafo completo a SerializedGraph.

        Args:
            graph:       El CSharpUnifiedGraph a serializar.
            model:       ParsedCSharpModel para metadata adicional (opcional).
            analysis_id: ID del análisis para trazabilidad en MongoDB.

        Returns:
            SerializedGraph listo para persistir o exportar.
        """
        t_start = datetime.now(timezone.utc)

        # Serializar nodos
        serialized_nodes = [
            self._serialize_node(node)
            for node in graph._nodes.values()
        ]

        # Serializar aristas
        serialized_edges = [
            self._serialize_edge(edge)
            for edge in graph._edges.values()
        ]

        # Extraer IDs de nodos clasificados
        source_ids    = list(graph._source_node_ids)
        sink_ids      = list(graph._sink_node_ids)
        sanitizer_ids = list(graph._sanitizer_node_ids)
        tainted_ids   = [n.node_id for n in graph.tainted_nodes]
        tainted_sink_ids = [n.node_id for n in graph.tainted_sinks]

        # Metadata del modelo
        framework       = model.metadata.framework if model else None
        files_analyzed  = list(model.metadata.files) if model else []
        lang_version    = model.metadata.language_version if model else None

        serialized_at = t_start.isoformat()

        s = SerializedGraph(
            schema_version=GRAPH_SCHEMA_VERSION,
            project_name=graph.project_name,
            analysis_id=analysis_id,
            serialized_at=serialized_at,
            stats=graph.stats(),
            nodes=serialized_nodes,
            edges=serialized_edges,
            source_node_ids=source_ids,
            sink_node_ids=sink_ids,
            sanitizer_node_ids=sanitizer_ids,
            tainted_node_ids=tainted_ids,
            tainted_sink_ids=tainted_sink_ids,
            framework=framework,
            files_analyzed=files_analyzed,
            language_version=lang_version,
        )

        elapsed_ms = (datetime.now(timezone.utc) - t_start).total_seconds() * 1000
        logger.info(
            "GraphSerializer: grafo serializado — "
            "%d nodos, %d aristas, %d tainted en %.0f ms",
            len(serialized_nodes),
            len(serialized_edges),
            len(tainted_ids),
            elapsed_ms,
        )
        return s

    def serialize_for_mongodb(
        self,
        graph:       CSharpUnifiedGraph,
        model:       ParsedCSharpModel | None = None,
        analysis_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Serializa el grafo en formato optimizado para MongoDB.

        Diferencias vs serialize():
          • Nodos y aristas se almacenan en arrays separados con referencias
          • Se añaden índices de búsqueda (taint_state, kind, file)
          • Los IDs se normalizan para uso como _id en MongoDB
        """
        s = self.serialize(graph, model, analysis_id)
        doc = s.to_dict()

        # Añadir campos de MongoDB
        if analysis_id:
            doc["_id"] = analysis_id
        doc["created_at"] = datetime.now(timezone.utc).isoformat()

        # Índices de búsqueda por taint state
        doc["has_tainted_sinks"] = len(s.tainted_sink_ids) > 0
        doc["tainted_sink_count"] = len(s.tainted_sink_ids)

        # Índice por archivo para queries de archivos específicos
        files_with_sinks = list({
            n["file"] for n in s.nodes
            if n.get("kind") == NodeKind.KNOWN_SINK.name
            and n.get("file")
        })
        doc["files_with_sinks"] = files_with_sinks

        return doc

    # ─────────────────────────────────────────────────────────────────────────
    #  SERIALIZACIÓN PARCIAL — SUBGRAFO DE TAINT
    # ─────────────────────────────────────────────────────────────────────────

    def serialize_taint_subgraph(
        self,
        graph:          CSharpUnifiedGraph,
        source_node_id: str | None = None,
        sink_node_id:   str | None = None,
    ) -> dict[str, Any]:
        """
        Serializa solo el subgrafo relevante para taint analysis.

        Si source_node_id y sink_node_id se proporcionan, extrae
        los caminos entre ellos. Si no, retorna todos los nodos tainted.

        Útil para generar el "evidence graph" en reportes de vulnerabilidades.
        """
        if source_node_id and sink_node_id:
            # Obtener caminos de taint entre source y sink
            paths = graph.find_taint_paths(source_node_id, sink_node_id)
            node_ids_in_paths: set[str] = set()
            for path in paths:
                for node in path:
                    node_ids_in_paths.add(node.node_id)

            relevant_nodes = [
                graph._nodes[nid]
                for nid in node_ids_in_paths
                if nid in graph._nodes
            ]
        else:
            # Todos los nodos tainted + sus vecinos inmediatos
            relevant_nodes = list(graph.tainted_nodes)
            for tainted in list(relevant_nodes):
                for succ in graph.successors(tainted.node_id):
                    if succ not in relevant_nodes:
                        relevant_nodes.append(succ)

        # Aristas entre nodos del subgrafo
        relevant_node_ids = {n.node_id for n in relevant_nodes}
        relevant_edges = [
            edge for edge in graph._edges.values()
            if edge.from_node_id in relevant_node_ids
            and edge.to_node_id in relevant_node_ids
        ]

        return {
            "subgraph_type": "taint_flow",
            "node_count":    len(relevant_nodes),
            "edge_count":    len(relevant_edges),
            "source_id":     source_node_id,
            "sink_id":       sink_node_id,
            "nodes": [self._serialize_node(n) for n in relevant_nodes],
            "edges": [self._serialize_edge(e) for e in relevant_edges],
        }

    def serialize_method_subgraph(
        self,
        graph:     CSharpUnifiedGraph,
        method_id: str,
    ) -> dict[str, Any]:
        """
        Serializa el subgrafo de un método específico.
        Útil para análisis intra-procedural aislado.
        """
        method_nodes = graph.get_nodes_in_method(method_id)
        method_node_ids = {n.node_id for n in method_nodes}

        method_edges = [
            e for e in graph._edges.values()
            if e.from_node_id in method_node_ids
            and e.to_node_id in method_node_ids
        ]

        return {
            "subgraph_type": "method",
            "method_id":     method_id,
            "node_count":    len(method_nodes),
            "edge_count":    len(method_edges),
            "nodes": [self._serialize_node(n) for n in method_nodes],
            "edges": [self._serialize_edge(e) for e in method_edges],
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  DESERIALIZACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def deserialize(self, data: dict[str, Any]) -> CSharpUnifiedGraph:
        """
        Reconstruye un CSharpUnifiedGraph desde un dict serializado.

        Usado para cargar grafos históricos desde MongoDB o disco.

        Args:
            data: Dict con la estructura de SerializedGraph.to_dict()

        Returns:
            CSharpUnifiedGraph reconstruido con todos sus nodos y aristas.
        """
        schema_version = data.get("schema_version", "unknown")
        if schema_version != GRAPH_SCHEMA_VERSION:
            logger.warning(
                "GraphSerializer: schema_version %s != %s — "
                "puede haber incompatibilidades.",
                schema_version, GRAPH_SCHEMA_VERSION,
            )

        graph = CSharpUnifiedGraph(
            project_name=data.get("project_name", "restored")
        )

        # Deserializar nodos
        for node_dict in data.get("nodes", []):
            node = self._deserialize_node(node_dict)
            if node:
                graph.add_node(node)

        # Deserializar aristas
        for edge_dict in data.get("edges", []):
            edge = self._deserialize_edge(edge_dict)
            if edge:
                graph.add_edge(edge)

        logger.info(
            "GraphSerializer: grafo deserializado — %d nodos, %d aristas",
            len(graph._nodes),
            len(graph._edges),
        )
        return graph

    def deserialize_from_json(self, json_str: str) -> CSharpUnifiedGraph:
        """Deserializa desde un string JSON."""
        data = json.loads(json_str)
        return self.deserialize(data)

    def deserialize_from_file(self, path: Path) -> CSharpUnifiedGraph:
        """Deserializa desde un archivo JSON."""
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return self.deserialize(data)

    # ─────────────────────────────────────────────────────────────────────────
    #  PERSISTENCIA EN DISCO
    # ─────────────────────────────────────────────────────────────────────────

    def save_to_file(
        self,
        graph:       CSharpUnifiedGraph,
        model:       ParsedCSharpModel | None = None,
        output_path: Path = Path("graph_output.json"),
        analysis_id: str | None = None,
        indent:      int = 2,
    ) -> Path:
        """
        Guarda el grafo serializado en un archivo JSON.

        Returns:
            Path al archivo creado.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        s = self.serialize(graph, model, analysis_id)
        json_str = s.to_json(indent=indent)

        with output_path.open("w", encoding="utf-8") as f:
            f.write(json_str)

        logger.info(
            "GraphSerializer: grafo guardado en %s (%.1f KB)",
            output_path,
            output_path.stat().st_size / 1024,
        )
        return output_path

    def save_taint_subgraph(
        self,
        graph:          CSharpUnifiedGraph,
        output_path:    Path,
        source_node_id: str | None = None,
        sink_node_id:   str | None = None,
    ) -> Path:
        """Guarda solo el subgrafo de taint."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        sub = self.serialize_taint_subgraph(graph, source_node_id, sink_node_id)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(sub, f, ensure_ascii=False, indent=2)

        return output_path

    # ─────────────────────────────────────────────────────────────────────────
    #  EXPORTACIÓN A FORMATOS DE VISUALIZACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def to_dot(
        self,
        graph:           CSharpUnifiedGraph,
        highlight_taint: bool = True,
        max_nodes:       int = 200,
    ) -> str:
        """
        Exporta el grafo a formato DOT (Graphviz) para visualización.

        Los nodos tainted se colorean en rojo, los sanitizadores en verde,
        los sinks en naranja, los sources en azul.

        Args:
            graph:           El grafo a exportar.
            highlight_taint: Si True, colorea nodos según su estado de taint.
            max_nodes:       Máximo de nodos a incluir (por performance de viz).

        Returns:
            String en formato DOT.
        """
        # Seleccionar nodos a incluir (priorizar los tainted)
        nodes_to_include: list[CSharpNode]
        if len(graph._nodes) > max_nodes:
            # Priorizar: tainted_sinks → tainted → sources → sinks → rest
            priority: list[CSharpNode] = (
                graph.tainted_sinks
                + [n for n in graph.tainted_nodes if not n.is_known_sink]
                + graph.source_nodes
                + [n for n in graph.sink_nodes if not n.is_tainted]
            )
            seen: set[str] = set()
            nodes_to_include = []
            for n in priority:
                if n.node_id not in seen and len(nodes_to_include) < max_nodes:
                    nodes_to_include.append(n)
                    seen.add(n.node_id)
        else:
            nodes_to_include = list(graph._nodes.values())

        included_ids = {n.node_id for n in nodes_to_include}

        lines: list[str] = [
            'digraph csharp_taint_graph {',
            '  graph [rankdir=LR, fontname="Helvetica", bgcolor="#1a1a2e"];',
            '  node  [fontname="Helvetica", fontsize=10, style=filled];',
            '  edge  [fontname="Helvetica", fontsize=9];',
            '',
        ]

        # Nodos
        for node in nodes_to_include:
            color, fontcolor, shape = self._dot_node_style(node, highlight_taint)
            safe_label = self._dot_escape(node.label[:50])
            file_short = node.file.split("/")[-1] if node.file else "?"
            tooltip = f"L{node.line} | {node.kind.name} | {file_short}"

            lines.append(
                f'  "{node.node_id}" ['
                f'label="{safe_label}\\nL{node.line}", '
                f'fillcolor="{color}", '
                f'fontcolor="{fontcolor}", '
                f'shape="{shape}", '
                f'tooltip="{tooltip}"'
                f'];'
            )

        lines.append('')

        # Aristas (solo entre nodos incluidos)
        for edge in graph._edges.values():
            if (edge.from_node_id not in included_ids
                    or edge.to_node_id not in included_ids):
                continue

            color, style = self._dot_edge_style(edge)
            label = edge.kind.value.replace("_", " ")
            lines.append(
                f'  "{edge.from_node_id}" -> "{edge.to_node_id}" ['
                f'label="{label}", '
                f'color="{color}", '
                f'style="{style}"'
                f'];'
            )

        lines.append('}')
        return '\n'.join(lines)

    def _dot_node_style(
        self,
        node:            CSharpNode,
        highlight_taint: bool,
    ) -> tuple[str, str, str]:
        """Retorna (fillcolor, fontcolor, shape) para un nodo DOT."""
        if highlight_taint:
            if node.is_tainted and node.is_known_sink:
                return "#ff4444", "#ffffff", "doubleoctagon"  # Rojo intenso
            if node.is_tainted:
                return "#ff8888", "#000000", "ellipse"         # Rojo suave
            if node.is_known_sink:
                return "#ff8c00", "#ffffff", "octagon"          # Naranja
            if node.is_known_source:
                return "#4488ff", "#ffffff", "parallelogram"    # Azul
            if node.is_known_sanitizer:
                return "#44bb44", "#ffffff", "hexagon"          # Verde
            if node.taint_state == TaintState.SANITIZED:
                return "#88dd88", "#000000", "ellipse"          # Verde suave

        # Default
        kind_colors: dict[NodeKind, str] = {
            NodeKind.PARAMETER:    "#6688cc",
            NodeKind.ASSIGNMENT:   "#88aacc",
            NodeKind.AWAIT_EXPR:   "#cc88cc",
            NodeKind.LAMBDA_CAPTURE: "#aa88cc",
            NodeKind.LINQ_EXPRESSION: "#88ccaa",
            NodeKind.STRING_INTERPOLATION: "#ccaa44",
            NodeKind.COLLECTION_ITEM: "#aacc88",
        }
        fill = kind_colors.get(node.kind, "#aaaaaa")
        return fill, "#000000", "ellipse"

    def _dot_edge_style(self, edge: CSharpEdge) -> tuple[str, str]:
        """Retorna (color, style) para una arista DOT."""
        if edge.kind == EdgeKind.FLOWS_TO:
            return "#ff6666", "bold"
        if edge.kind == EdgeKind.TAINTS:
            return "#ff0000", "bold"
        if edge.kind == EdgeKind.SANITIZES:
            return "#00aa00", "bold"
        if edge.kind in (EdgeKind.ALIASES, EdgeKind.CAPTURED_BY):
            return "#cc8800", "dashed"
        if edge.kind in (EdgeKind.CALLS, EdgeKind.RETURNED_BY):
            return "#6666ff", "dotted"
        if edge.kind in (EdgeKind.TRUE_BRANCH, EdgeKind.FALSE_BRANCH):
            return "#888888", "dashed"
        return "#666666", "solid"

    @staticmethod
    def _dot_escape(text: str) -> str:
        return (
            text.replace('"', '\\"')
                .replace('\n', '\\n')
                .replace('\r', '')
                .replace('<', '\\<')
                .replace('>', '\\>')
                .replace('{', '\\{')
                .replace('}', '\\}')
        )

    def to_graphml(self, graph: CSharpUnifiedGraph) -> str:
        """
        Exporta el grafo a formato GraphML (compatible con Gephi, yEd, Cytoscape).

        GraphML es un estándar XML para grafos — permite atributos en nodos y aristas.
        """
        lines: list[str] = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/graphml"',
            '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '  xsi:schemaLocation="http://graphml.graphdrawing.org/graphml '
            'http://graphml.graphdrawing.org/graphml/1.0rc/graphml.xsd">',
            '',
            '  <!-- Atributos de nodo -->',
            '  <key id="kind"        for="node" attr.name="kind"         attr.type="string"/>',
            '  <key id="label"       for="node" attr.name="label"        attr.type="string"/>',
            '  <key id="file"        for="node" attr.name="file"         attr.type="string"/>',
            '  <key id="line"        for="node" attr.name="line"         attr.type="int"/>',
            '  <key id="taint"       for="node" attr.name="taint_state"  attr.type="string"/>',
            '  <key id="symbol"      for="node" attr.name="symbol"       attr.type="string"/>',
            '  <!-- Atributos de arista -->',
            '  <key id="edge_kind"   for="edge" attr.name="edge_kind"    attr.type="string"/>',
            '  <key id="confidence"  for="edge" attr.name="confidence"   attr.type="double"/>',
            '',
            f'  <graph id="{graph.project_name}" edgedefault="directed">',
        ]

        for node in graph._nodes.values():
            lines.extend([
                f'    <node id="{node.node_id}">',
                f'      <data key="kind">{node.kind.name}</data>',
                f'      <data key="label">{self._dot_escape(node.label[:80])}</data>',
                f'      <data key="file">{node.file}</data>',
                f'      <data key="line">{node.line}</data>',
                f'      <data key="taint">{node.taint_state.value}</data>',
                f'      <data key="symbol">{node.resolved_symbol or ""}</data>',
                f'    </node>',
            ])

        for edge in graph._edges.values():
            lines.extend([
                f'    <edge id="{edge.edge_id}" '
                f'source="{edge.from_node_id}" '
                f'target="{edge.to_node_id}">',
                f'      <data key="edge_kind">{edge.kind.value}</data>',
                f'      <data key="confidence">{edge.confidence}</data>',
                f'    </edge>',
            ])

        lines.extend([
            '  </graph>',
            '</graphml>',
        ])

        return '\n'.join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS DE SERIALIZACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _serialize_node(self, node: CSharpNode) -> dict[str, Any]:
        """Convierte un CSharpNode a dict serializable."""
        return {
            "node_id":         node.node_id,
            "kind":            node.kind.name,
            "label":           node.label,
            "file":            node.file,
            "line":            node.line,
            "column":          node.column,
            "method_id":       node.method_id,
            "class_name":      node.class_name,
            "taint_state":     node.taint_state.value,
            "taint_label":     node.taint_label,
            "taint_origin":    node.taint_origin,
            "resolved_symbol": node.resolved_symbol,
            "resolved_type":   node.resolved_type,
            "is_async":        node.is_async,
            "is_in_loop":      node.is_in_loop,
            "is_in_try":       node.is_in_try,
            "attributes":      node.attributes,
            # Flags de clasificación para MongoDB queries
            "is_source":       node.is_known_source,
            "is_sink":         node.is_known_sink,
            "is_sanitizer":    node.is_known_sanitizer,
            "is_tainted":      node.is_tainted,
        }

    def _serialize_edge(self, edge: CSharpEdge) -> dict[str, Any]:
        """Convierte un CSharpEdge a dict serializable."""
        return {
            "edge_id":          edge.edge_id,
            "from_node_id":     edge.from_node_id,
            "to_node_id":       edge.to_node_id,
            "kind":             edge.kind.value,
            "label":            edge.label,
            "taint_label":      edge.taint_label,
            "confidence":       edge.confidence,
            "is_conditional":   edge.is_conditional,
            "argument_position": edge.argument_position,
            "via_alias":        edge.via_alias,
        }

    def _deserialize_node(self, data: dict[str, Any]) -> CSharpNode | None:
        """Reconstruye un CSharpNode desde un dict."""
        try:
            kind = NodeKind[data["kind"]]
            taint_state_val = data.get("taint_state", TaintState.UNKNOWN.value)
            taint_state = TaintState(taint_state_val)

            return CSharpNode(
                node_id=data["node_id"],
                kind=kind,
                label=data.get("label", ""),
                file=data.get("file", ""),
                line=data.get("line", 0),
                column=data.get("column", 0),
                method_id=data.get("method_id"),
                class_name=data.get("class_name"),
                taint_state=taint_state,
                taint_label=data.get("taint_label"),
                taint_origin=data.get("taint_origin"),
                resolved_symbol=data.get("resolved_symbol"),
                resolved_type=data.get("resolved_type"),
                is_async=data.get("is_async", False),
                is_in_loop=data.get("is_in_loop", False),
                is_in_try=data.get("is_in_try", False),
                attributes=data.get("attributes", {}),
            )
        except (KeyError, ValueError) as exc:
            logger.warning("GraphSerializer: error deserializando nodo: %s", exc)
            return None

    def _deserialize_edge(self, data: dict[str, Any]) -> CSharpEdge | None:
        """Reconstruye un CSharpEdge desde un dict."""
        try:
            kind = EdgeKind(data["kind"])
            return CSharpEdge(
                edge_id=data["edge_id"],
                from_node_id=data["from_node_id"],
                to_node_id=data["to_node_id"],
                kind=kind,
                label=data.get("label", ""),
                taint_label=data.get("taint_label"),
                confidence=data.get("confidence", 1.0),
                is_conditional=data.get("is_conditional", False),
                argument_position=data.get("argument_position"),
                via_alias=data.get("via_alias"),
            )
        except (KeyError, ValueError) as exc:
            logger.warning("GraphSerializer: error deserializando arista: %s", exc)
            return None

    # ─────────────────────────────────────────────────────────────────────────
    #  DIFF DE GRAFOS
    # ─────────────────────────────────────────────────────────────────────────

    def diff(
        self,
        graph_before: CSharpUnifiedGraph,
        graph_after:  CSharpUnifiedGraph,
    ) -> dict[str, Any]:
        """
        Calcula la diferencia de estado de taint entre dos versiones del grafo.
        Útil para comparar el grafo antes y después del taint propagation.

        Returns:
            Dict con:
              newly_tainted:    nodos que pasaron a tainted en graph_after
              newly_sanitized:  nodos que pasaron a sanitized en graph_after
              unchanged_tainted: nodos tainted en ambas versiones
        """
        tainted_before = {n.node_id for n in graph_before.tainted_nodes}
        tainted_after  = {n.node_id for n in graph_after.tainted_nodes}

        sanitized_after = {
            n.node_id for n in graph_after._nodes.values()
            if n.taint_state == TaintState.SANITIZED
        }

        newly_tainted    = tainted_after - tainted_before
        newly_sanitized  = sanitized_after
        unchanged_tainted = tainted_before & tainted_after

        return {
            "newly_tainted_count":    len(newly_tainted),
            "newly_sanitized_count":  len(newly_sanitized),
            "unchanged_tainted_count": len(unchanged_tainted),
            "newly_tainted_nodes": [
                self._serialize_node(graph_after._nodes[nid])
                for nid in newly_tainted
                if nid in graph_after._nodes
            ],
            "newly_sanitized_nodes": [
                self._serialize_node(graph_after._nodes[nid])
                for nid in newly_sanitized
                if nid in graph_after._nodes
            ],
        }