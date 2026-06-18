# =============================================================================
#  csharp-sast / core / graph / taint_propagator.py
# =============================================================================
#
#  MOTOR DE PROPAGACIÓN DE TAINT ESPECÍFICO PARA C#
#  ──────────────────────────────────────────────────
#  Propaga el estado de taint desde los nodos source a través del
#  CSharpUnifiedGraph hasta los nodos sink, respetando:
#    • Sanitizadores que interrumpen el flujo
#    • Ramificaciones condicionales (taint parcial)
#    • Flujo async/await (el taint persiste a través de continuaciones)
#    • Alias y colecciones (propagación transitiva)
#    • Flujo inter-procedural (a través de límites de método)
#    • String interpolation y concatenación (vector de SQL injection)
#
#  ALGORITMO PRINCIPAL:
#    BFS dirigido desde cada source node:
#      1. Añadir todos los sources como nodos inicialmente tainted
#      2. Para cada nodo tainted, propagar a sus sucesores via DataFlow edges
#      3. Si el sucesor es un SANITIZADOR que cubre el tipo de vuln → detener
#      4. Si el sucesor es un SINK → registrar TaintResult
#      5. Ajustar confianza según: branch conditions, loops, sanitizers parciales
#
#  FEATURES ESPECÍFICOS DE C#:
#    • async/await: await Task<T> no detiene el taint — el awaiter
#      recibe el mismo valor. La propagación continúa después del await.
#    • LINQ: .Where(x => condition) propaga taint si el source está
#      en la colección. .Select(x => x.Prop) propaga la propiedad.
#    • Generic types: List<T>, Dictionary<K,V> propagan taint cuando
#      se añade un elemento tainted (Add, [], indexer assignment).
#    • Extension methods: el this parameter actúa igual que un parámetro normal.
#    • Null coalescing: x ?? default — si x está tainted, el resultado
#      también lo está (el taint no desaparece con null checks).
#    • Pattern matching: switch (x) { case string s: } — s hereda taint de x.
#
#  CONFIDENCE SCORING:
#    Cada TaintResult tiene un score de confianza (0.0 - 1.0):
#      1.0  → fuente directa → sink directo, sin ramas condicionales
#      0.9  → a través de una asignación/alias
#      0.8  → a través de múltiples pasos de data flow
#      0.7  → flujo condicional (puede o no ocurrir)
#      0.6  → flujo inter-procedural
#      0.5  → a través de colección o LINQ
#      0.4  → múltiples caminos condicionales complejos
#    El sanitizador parcial reduce confidence pero no la lleva a 0.
#
#  INTEGRACIÓN CON EL PIPELINE:
#    TaintAnalyzer (analyzers/taint_analyzer.py)
#      → llama a TaintPropagator.propagate()
#      → obtiene list[TaintResult]
#      → convierte a list[TaintFinding]
#    VulnerabilityClassifier consume los TaintFinding.
#
# =============================================================================

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
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
from core.rules.rule_loader import RuleLoader

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

class PropagationStopReason(Enum):
    """Razón por la que el taint se detuvo en un nodo."""
    REACHED_SINK          = auto()   # Llegó a un sink → vulnerabilidad
    SANITIZER_FULL        = auto()   # Sanitizador con confidence >= 0.95
    SANITIZER_PARTIAL     = auto()   # Sanitizador presente pero < 0.95 confidence
    CYCLE_DETECTED        = auto()   # Ciclo en el grafo (loop ya visitado)
    MAX_DEPTH_REACHED     = auto()   # Profundidad máxima de BFS alcanzada
    NO_SUCCESSORS         = auto()   # Nodo sin sucesores de data flow
    TYPE_CONVERSION       = auto()   # Conversión de tipo segura (int.TryParse, etc.)


@dataclass
class TaintStep:
    """Un paso en la propagación de taint."""
    node_id:        str
    node_kind:      str            # NodeKind.name
    label:          str
    file:           str
    line:           int
    edge_kind:      str | None     # EdgeKind del salto que llegó aquí
    taint_label:    str            # Label del taint propagado
    confidence:     float          # Confianza acumulada hasta este paso
    is_conditional: bool = False   # El flujo que llegó aquí era condicional
    via_alias:      str | None = None


@dataclass
class TaintResult:
    """
    Resultado de una propagación de taint desde source hasta sink.
    Input directo del VulnerabilityClassifier para generar findings.
    """
    # IDs de los nodos extremos
    source_node_id:     str
    sink_node_id:       str

    # Metadatos de source
    source_label:       str
    source_taint_label: str       # "USER_INPUT", "EXTERNAL_INPUT", etc.
    source_file:        str
    source_line:        int

    # Metadatos de sink
    sink_label:         str
    sink_symbol:        str | None
    sink_file:          str
    sink_line:          int
    sink_arg_position:  int | None

    # Contexto
    method_id:          str | None
    class_name:         str | None
    is_in_loop:         bool
    is_async_flow:      bool

    # Calidad del resultado
    confidence:         float
    path_length:        int        # Número de pasos source→sink
    is_definitely_reachable: bool  # False si es solo condicional

    # Sanitizadores detectados en el camino (pero no suficientes)
    has_partial_sanitizer:  bool = False
    partial_sanitizer_symbol: str | None = None

    # Camino detallado (para reportes)
    taint_path: list[TaintStep] = field(default_factory=list)

    # Evidence crudo
    raw_evidence: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"TaintResult("
            f"conf={self.confidence:.2f}, "
            f"{self.source_file.split('/')[-1]}:{self.source_line}"
            f" → {self.sink_file.split('/')[-1]}:{self.sink_line})"
        )


@dataclass
class PropagationStats:
    """Estadísticas de una ejecución de propagación."""
    sources_processed:    int = 0
    nodes_visited:        int = 0
    taint_results:        int = 0
    sanitizers_blocked:   int = 0
    cycles_detected:      int = 0
    max_depth_hits:       int = 0
    async_flows:          int = 0
    loop_flows:           int = 0
    inter_procedural:     int = 0

    def summary(self) -> str:
        return (
            f"PropagationStats("
            f"sources={self.sources_processed}, "
            f"visited={self.nodes_visited}, "
            f"results={self.taint_results}, "
            f"blocked_by_sanitizer={self.sanitizers_blocked}, "
            f"cycles={self.cycles_detected})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  ESTADO INTERNO DEL BFS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _PropagationState:
    """
    Estado de la propagación BFS desde un source específico.
    Una instancia por source node en la propagación.
    """
    source_node:    CSharpNode
    taint_label:    str
    visited:        set[str] = field(default_factory=set)
    path_so_far:    list[TaintStep] = field(default_factory=list)
    confidence:     float = 1.0
    has_conditional: bool = False
    has_async:       bool = False
    has_sanitizer:   bool = False
    sanitizer_symbol: str | None = None
    depth:           int = 0


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURACIÓN DEL PROPAGADOR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PropagatorConfig:
    """Configuración del comportamiento del taint propagator."""

    # Profundidad máxima del BFS (previene explosión combinatoria)
    max_depth: int = 30

    # Máximo de caminos a explorar por source (previene timeout)
    max_paths_per_source: int = 50

    # Si True, el taint se propaga a través de ramas condicionales
    # (genera más resultados pero con menor confidence)
    follow_conditional_branches: bool = True

    # Si True, propagar a través de límites de método (inter-procedural)
    inter_procedural: bool = True

    # Si True, el taint en loops aumenta la severidad
    track_loops: bool = True

    # Si True, propagar a través de async/await
    follow_async: bool = True

    # Umbral mínimo de confidence para reportar un TaintResult
    min_confidence_threshold: float = 0.30

    # Si True, detener propagación en sanitizadores con confidence >= este umbral
    sanitizer_confidence_threshold: float = 0.90

    # Si True, generar paths detallados (más memoria, más útil para reportes)
    generate_detailed_paths: bool = True


# ─────────────────────────────────────────────────────────────────────────────
#  TAINT PROPAGATOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class CSharpTaintPropagator:
    """
    Motor de propagación de taint para C# sobre el CSharpUnifiedGraph.

    Implementa BFS dirigido con tracking de confianza, sanitizadores
    y características específicas de C# (async, LINQ, generics).

    Uso:
        propagator = CSharpTaintPropagator(rule_loader, config)
        results, stats = propagator.propagate(graph, model)
        # results: list[TaintResult] → pasa a TaintAnalyzer
    """

    def __init__(
        self,
        rule_loader: RuleLoader,
        config:      PropagatorConfig | None = None,
    ) -> None:
        self._rules   = rule_loader
        self._config  = config or PropagatorConfig()

        # Índices del rule_loader (cargados una vez)
        self._sanitizer_confidence = rule_loader.get_sanitizer_confidence_map()
        self._sanitizer_vulns      = rule_loader.get_sanitizer_vulnerability_map()
        self._source_taint_labels  = rule_loader.get_source_taint_labels()

    # ─────────────────────────────────────────────────────────────────────────
    #  MÉTODO PRINCIPAL
    # ─────────────────────────────────────────────────────────────────────────

    def propagate(
        self,
        graph: CSharpUnifiedGraph,
        model: ParsedCSharpModel,
    ) -> tuple[list[TaintResult], PropagationStats]:
        """
        Ejecuta la propagación de taint completa sobre el grafo unificado.

        Proceso:
          1. Identificar todos los source nodes del grafo
          2. Para cada source, ejecutar BFS hacia los sinks
          3. Recolectar y deduplicar TaintResult
          4. Actualizar el estado de taint en el grafo (in-place)

        Args:
            graph: CSharpUnifiedGraph construido por CSharpGraphBuilder.
            model: ParsedCSharpModel para metadata adicional.

        Returns:
            (lista_de_resultados, estadísticas_de_propagación)
        """
        stats   = PropagationStats()
        results: list[TaintResult] = []

        source_nodes = self._identify_sources(graph)
        stats.sources_processed = len(source_nodes)

        logger.info(
            "TaintPropagator: iniciando propagación desde %d sources "
            "en %d nodos totales.",
            len(source_nodes),
            len(graph._nodes),
        )

        for source_node in source_nodes:
            taint_label = self._get_taint_label(source_node)

            # Marcar el source como tainted en el grafo
            source_node.mark_tainted(taint_label, source_node.node_id)

            # BFS desde este source
            source_results = self._bfs_from_source(
                source_node, taint_label, graph, model, stats
            )
            results.extend(source_results)

        # Deduplicar resultados (mismo source+sink)
        results = self._deduplicate_results(results)
        stats.taint_results = len(results)

        # Actualizar el grafo con el estado de taint final
        self._update_graph_taint_state(results, graph)

        logger.info(
            "TaintPropagator: %s",
            stats.summary(),
        )
        return results, stats

    def propagate_from_node(
        self,
        source_node_id: str,
        taint_label:    str,
        graph:          CSharpUnifiedGraph,
        model:          ParsedCSharpModel,
    ) -> list[TaintResult]:
        """
        Propaga taint desde un único nodo source específico.
        Útil para análisis incremental o pruebas unitarias.
        """
        source_node = graph.get_node(source_node_id)
        if not source_node:
            return []

        stats = PropagationStats()
        source_node.mark_tainted(taint_label, source_node_id)
        return self._bfs_from_source(source_node, taint_label, graph, model, stats)

    # ─────────────────────────────────────────────────────────────────────────
    #  BFS DESDE UN SOURCE
    # ─────────────────────────────────────────────────────────────────────────

    def _bfs_from_source(
        self,
        source_node: CSharpNode,
        taint_label: str,
        graph:       CSharpUnifiedGraph,
        model:       ParsedCSharpModel,
        stats:       PropagationStats,
    ) -> list[TaintResult]:
        """
        BFS de taint desde un nodo source.

        Estructura de la queue: (node_id, PropagationState)
        Cada elemento de la queue representa un camino parcial
        de propagación hasta ese nodo.
        """
        results: list[TaintResult] = []
        paths_explored = 0

        # Cola BFS: (node_id, _PropagationState)
        initial_step = TaintStep(
            node_id=source_node.node_id,
            node_kind=source_node.kind.name,
            label=source_node.label,
            file=source_node.file,
            line=source_node.line,
            edge_kind=None,
            taint_label=taint_label,
            confidence=1.0,
        )
        initial_state = _PropagationState(
            source_node=source_node,
            taint_label=taint_label,
            visited={source_node.node_id},
            path_so_far=[initial_step],
            confidence=1.0,
        )

        queue: deque[tuple[str, _PropagationState]] = deque()
        queue.append((source_node.node_id, initial_state))

        while queue and paths_explored < self._config.max_paths_per_source:
            current_id, state = queue.popleft()
            stats.nodes_visited += 1

            if state.depth >= self._config.max_depth:
                stats.max_depth_hits += 1
                continue

            # Explorar sucesores de data flow
            outgoing_edges = graph.get_outgoing_edges(current_id)

            for edge in outgoing_edges:
                # Solo seguir aristas de data flow
                if not self._is_data_flow_edge(edge):
                    continue

                successor_id = edge.to_node_id
                successor    = graph.get_node(successor_id)
                if not successor:
                    continue

                # Evitar ciclos (detectar loops)
                if successor_id in state.visited:
                    stats.cycles_detected += 1
                    continue

                # Calcular nueva confianza para este paso
                new_confidence = self._calculate_step_confidence(
                    state.confidence, edge, successor, state
                )

                if new_confidence < self._config.min_confidence_threshold:
                    continue  # Confianza demasiado baja para seguir

                # Verificar si es un sanitizador
                stop_reason = self._check_sanitizer(successor, state.taint_label)

                if stop_reason == PropagationStopReason.SANITIZER_FULL:
                    # Sanitizador completo → marcar en grafo y detener
                    stats.sanitizers_blocked += 1
                    successor.mark_sanitized()
                    logger.debug(
                        "TaintPropagator: taint bloqueado por sanitizador '%s'",
                        successor.label[:40],
                    )
                    continue

                # Construir el paso del camino
                new_step = TaintStep(
                    node_id=successor_id,
                    node_kind=successor.kind.name,
                    label=successor.label,
                    file=successor.file,
                    line=successor.line,
                    edge_kind=edge.kind.value,
                    taint_label=state.taint_label,
                    confidence=new_confidence,
                    is_conditional=edge.is_conditional,
                    via_alias=edge.via_alias,
                )

                # Actualizar estado de taint en el grafo
                successor.mark_tainted(state.taint_label, source_node.node_id)

                new_path = state.path_so_far + [new_step]

                # ── ¿Llegamos a un sink? ─────────────────────────────────────
                if successor.is_known_sink:
                    result = self._build_taint_result(
                        source_node=source_node,
                        sink_node=successor,
                        taint_label=state.taint_label,
                        confidence=new_confidence,
                        path=new_path,
                        state=state,
                        model=model,
                    )
                    results.append(result)
                    paths_explored += 1
                    logger.debug(
                        "TaintPropagator: sink encontrado '%s' conf=%.2f",
                        successor.label[:40], new_confidence,
                    )
                    continue  # No seguir desde un sink

                # ── Propagar a través de async/await ─────────────────────────
                is_async_hop = (
                    successor.kind == NodeKind.AWAIT_EXPR
                    or successor.is_async
                )
                if is_async_hop:
                    stats.async_flows += 1

                # ── Enqueue el sucesor para seguir propagando ─────────────────
                new_state = _PropagationState(
                    source_node=state.source_node,
                    taint_label=state.taint_label,
                    visited=state.visited | {successor_id},
                    path_so_far=new_path,
                    confidence=new_confidence,
                    has_conditional=state.has_conditional or edge.is_conditional,
                    has_async=state.has_async or is_async_hop,
                    has_sanitizer=(
                        stop_reason == PropagationStopReason.SANITIZER_PARTIAL
                    ),
                    sanitizer_symbol=self._get_sanitizer_symbol(successor),
                    depth=state.depth + 1,
                )
                queue.append((successor_id, new_state))

        return results

    # ─────────────────────────────────────────────────────────────────────────
    #  IDENTIFICACIÓN DE SOURCES
    # ─────────────────────────────────────────────────────────────────────────

    def _identify_sources(self, graph: CSharpUnifiedGraph) -> list[CSharpNode]:
        """
        Identifica todos los nodos que actúan como fuente de taint.

        Sources en C#:
          1. Nodos marcados como KNOWN_SOURCE (HttpRequest.Query, etc.)
          2. Nodos PARAMETER de métodos entry point (action methods, WCF ops)
          3. Nodos de datos de red o consola
          4. Resultados de BD como sources de second-order injection
        """
        sources: list[CSharpNode] = []

        for node in graph._nodes.values():
            if node.is_known_source:
                sources.append(node)
                continue

            # Parámetros de métodos entry point son sources implícitas
            if node.kind == NodeKind.PARAMETER:
                if self._is_entry_point_parameter(node, graph):
                    sources.append(node)
                    continue

            # String interpolation/concatenation con datos no literales
            if node.kind in (
                NodeKind.STRING_INTERPOLATION,
                NodeKind.STRING_CONCAT,
            ):
                if self._has_tainted_predecessor(node, graph):
                    sources.append(node)

        logger.debug(
            "TaintPropagator: %d sources identificados "
            "(%d known_source, %d implicit).",
            len(sources),
            sum(1 for s in sources if s.is_known_source),
            sum(1 for s in sources if not s.is_known_source),
        )
        return sources

    def _is_entry_point_parameter(
        self,
        param_node: CSharpNode,
        graph:      CSharpUnifiedGraph,
    ) -> bool:
        """
        True si el parámetro pertenece a un método que es entry point
        (action method de ASP.NET Core, operación WCF, etc.).

        La detección se hace por:
          1. El nodo tiene atributos que indican entry point
          2. El método contenedor tiene anotaciones HTTP (HttpGet, etc.)
        """
        attrs = param_node.attributes

        # Si el node tiene marcado explícito de entry point
        if attrs.get("is_entry_point"):
            return True

        # Verificar por nodos de la misma clase en el grafo
        # Si hay nodos KNOWN_SOURCE en el mismo método → el método recibe user input
        if param_node.method_id:
            method_nodes = graph.get_nodes_in_method(param_node.method_id)
            return any(n.is_known_source for n in method_nodes)

        return False

    def _has_tainted_predecessor(
        self,
        node:  CSharpNode,
        graph: CSharpUnifiedGraph,
    ) -> bool:
        """True si algún predecesor directo del nodo ya está tainted."""
        for pred in graph.predecessors(node.node_id):
            if pred.is_tainted or pred.is_known_source:
                return True
        return False

    # ─────────────────────────────────────────────────────────────────────────
    #  EVALUACIÓN DE SANITIZADORES
    # ─────────────────────────────────────────────────────────────────────────

    def _check_sanitizer(
        self,
        node:        CSharpNode,
        taint_label: str,
    ) -> PropagationStopReason | None:
        """
        Verifica si un nodo sanitiza el taint.

        Retorna:
          SANITIZER_FULL     → el taint se detiene completamente
          SANITIZER_PARTIAL  → el taint continúa con menor confidence
          None               → no es un sanitizador (o no aplica)

        La evaluación considera:
          1. ¿Es el nodo un sanitizador conocido?
          2. ¿El sanitizador es relevante para el tipo de taint?
          3. ¿La confidence del sanitizador supera el umbral?
        """
        if not node.is_known_sanitizer:
            return None

        # Obtener confidence del sanitizador
        symbol    = node.resolved_symbol or ""
        confidence = self._get_sanitizer_confidence(symbol)

        if confidence == 0.0:
            return None  # No reconocido como sanitizador

        # Verificar si el sanitizador cubre el tipo de vulnerabilidad
        # que podría causar el taint_label
        sanitizes_vulns = self._sanitizer_vulns.get(symbol, [])
        if sanitizes_vulns:
            # Verificar si el label de taint implica una vuln que este sanitizador cubre
            relevant = self._taint_label_relevant_for_sanitizer(
                taint_label, sanitizes_vulns
            )
            if not relevant:
                return None  # Sanitizador no aplica para este tipo de taint

        # Determinar si es completo o parcial
        threshold = self._config.sanitizer_confidence_threshold
        if confidence >= threshold:
            return PropagationStopReason.SANITIZER_FULL
        return PropagationStopReason.SANITIZER_PARTIAL

    def _get_sanitizer_confidence(self, symbol: str) -> float:
        """Obtiene la confidence de un sanitizador por prefijo de símbolo."""
        # Búsqueda exacta
        if symbol in self._sanitizer_confidence:
            return self._sanitizer_confidence[symbol]
        # Búsqueda por prefijo
        for prefix, confidence in self._sanitizer_confidence.items():
            if symbol.startswith(prefix):
                return confidence
        return 0.0

    def _taint_label_relevant_for_sanitizer(
        self,
        taint_label:    str,
        sanitizes_vulns: list[str],
    ) -> bool:
        """
        Determina si el sanitizador es relevante para el tipo de taint.

        USER_INPUT puede causar cualquier tipo de injection → un sanitizador
        de SQL_INJECTION es relevante para USER_INPUT dirigido a un SqlCommand.

        La lógica es: si el taint label es USER_INPUT o NETWORK_INPUT,
        el sanitizador es siempre relevante. Para labels más específicos
        (STORED_INPUT, ENVIRONMENT_INPUT), verificar la lista explícita.
        """
        if taint_label in ("USER_INPUT", "NETWORK_INPUT"):
            return True  # Estos labels pueden causar cualquier injection

        # Para otros labels, verificar si el sanitizador cubre alguna vuln
        # que el label podría causar
        label_to_vulns = {
            "EXTERNAL_INPUT":   {"SQL_INJECTION", "XSS", "SSRF", "PATH_TRAVERSAL"},
            "STORED_INPUT":     {"SQL_INJECTION", "XSS", "LOG_INJECTION"},
            "ENVIRONMENT_INPUT": {"COMMAND_INJECTION", "PATH_TRAVERSAL"},
        }
        relevant_vulns = label_to_vulns.get(taint_label, set())
        return bool(relevant_vulns & set(sanitizes_vulns))

    def _get_sanitizer_symbol(self, node: CSharpNode) -> str | None:
        """Retorna el símbolo del sanitizador si el nodo es uno."""
        if node.is_known_sanitizer:
            return node.resolved_symbol
        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  CÁLCULO DE CONFIANZA
    # ─────────────────────────────────────────────────────────────────────────

    def _calculate_step_confidence(
        self,
        current_confidence: float,
        edge:               CSharpEdge,
        successor:          CSharpNode,
        state:              _PropagationState,
    ) -> float:
        """
        Calcula la nueva confianza después de propagar por una arista.

        Factores que REDUCEN la confianza:
          • Arista condicional (el flujo puede no ocurrir)
          • Flujo a través de alias (un paso de indirección)
          • Flujo inter-procedural (cruce de límite de método)
          • Nodo en un loop (puede ejecutarse 0 o N veces)
          • Flujo a través de colección (elemento puede no ser el tainted)
          • Awaitable (el contexto cambia de thread)
          • Sanitizador parcial en el camino

        Factores que MANTIENEN la confianza:
          • Flujo directo (FLOWS_TO sin alias)
          • Mismo método
          • Nodo no en loop
        """
        confidence = current_confidence

        # ── Reducción por tipo de arista ──────────────────────────────────────
        if edge.is_conditional:
            confidence *= 0.80   # Flujo condicional → no siempre ocurre
        if edge.kind == EdgeKind.ALIASES:
            confidence *= 0.92   # Un paso de alias → ligeramente menos cierto
        if edge.kind == EdgeKind.RETURNED_BY:
            confidence *= 0.85   # Flujo inter-procedural
        if edge.kind == EdgeKind.CAPTURED_BY:
            confidence *= 0.88   # Lambda capture → puede ser complejo

        # ── Reducción por características del sucesor ──────────────────────────
        if successor.is_in_loop:
            confidence *= 0.90   # En loop → puede no ejecutarse con taint
        if successor.kind in (NodeKind.COLLECTION_ITEM, NodeKind.LINQ_EXPRESSION):
            confidence *= 0.85   # A través de colección/LINQ → indirecto
        if successor.kind == NodeKind.AWAIT_EXPR:
            confidence *= 0.95   # Await → el taint persiste pero el contexto cambia
        if successor.kind == NodeKind.LAMBDA_CAPTURE:
            confidence *= 0.88   # Lambda capture → complicado de rastrear

        # ── Reducción por estado del camino ──────────────────────────────────
        if state.has_sanitizer:
            confidence *= 0.75   # Sanitizador parcial en el camino

        # ── Reducción por profundidad (cadenas largas son menos ciertas) ─────
        if state.depth > 5:
            confidence *= 0.95 ** (state.depth - 5)

        # ── Reducción por alias transitivo ───────────────────────────────────
        if edge.via_alias:
            confidence *= 0.92

        return round(confidence, 4)

    # ─────────────────────────────────────────────────────────────────────────
    #  CONSTRUCCIÓN DE TAINTRESULT
    # ─────────────────────────────────────────────────────────────────────────

    def _build_taint_result(
        self,
        source_node: CSharpNode,
        sink_node:   CSharpNode,
        taint_label: str,
        confidence:  float,
        path:        list[TaintStep],
        state:       _PropagationState,
        model:       ParsedCSharpModel,
    ) -> TaintResult:
        """Construye un TaintResult completo desde un camino de propagación."""

        # Determinar si el flujo es definitivo o condicional
        is_definitely = not state.has_conditional and confidence >= 0.85

        # Obtener posición del argumento tainted en el sink
        sink_arg_pos = self._find_tainted_arg_position(sink_node, model)

        # Obtener nombre de clase del método contenedor del sink
        class_name = sink_node.class_name
        method_id  = sink_node.method_id

        return TaintResult(
            source_node_id=source_node.node_id,
            sink_node_id=sink_node.node_id,
            source_label=source_node.label,
            source_taint_label=taint_label,
            source_file=source_node.file,
            source_line=source_node.line,
            sink_label=sink_node.label,
            sink_symbol=sink_node.resolved_symbol,
            sink_file=sink_node.file,
            sink_line=sink_node.line,
            sink_arg_position=sink_arg_pos,
            method_id=method_id,
            class_name=class_name,
            is_in_loop=sink_node.is_in_loop,
            is_async_flow=state.has_async,
            confidence=confidence,
            path_length=len(path),
            is_definitely_reachable=is_definitely,
            has_partial_sanitizer=state.has_sanitizer,
            partial_sanitizer_symbol=state.sanitizer_symbol,
            taint_path=path if self._config.generate_detailed_paths else [],
            raw_evidence={
                "depth":             state.depth,
                "has_conditional":   state.has_conditional,
                "has_async":         state.has_async,
                "path_node_kinds":   [s.node_kind for s in path],
                "via_aliases":       [s.via_alias for s in path if s.via_alias],
            },
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS INTERNOS
    # ─────────────────────────────────────────────────────────────────────────

    def _is_data_flow_edge(self, edge: CSharpEdge) -> bool:
        """True si la arista representa flujo de datos (no control flow)."""
        data_flow_kinds = {
            EdgeKind.FLOWS_TO,
            EdgeKind.ALIASES,
            EdgeKind.ASSIGNED_TO,
            EdgeKind.CAPTURED_BY,
            EdgeKind.RETURNED_BY,
            EdgeKind.TAINTS,
        }
        return edge.kind in data_flow_kinds

    def _get_taint_label(self, source_node: CSharpNode) -> str:
        """Determina el taint label de un source node."""
        if source_node.resolved_symbol:
            # Buscar en el catálogo de sources por prefijo
            for prefix, label in self._source_taint_labels.items():
                if source_node.resolved_symbol.startswith(prefix):
                    return label

        # Para parámetros de entry points → USER_INPUT
        if source_node.kind == NodeKind.PARAMETER:
            return "USER_INPUT"

        # Para nodos de red → NETWORK_INPUT
        if source_node.kind in (NodeKind.STRING_INTERPOLATION, NodeKind.STRING_CONCAT):
            return "USER_INPUT"

        return "USER_INPUT"  # Default conservador

    def _find_tainted_arg_position(
        self,
        sink_node: CSharpNode,
        model:     ParsedCSharpModel,
    ) -> int | None:
        """Encuentra la posición del argumento tainted en un sink."""
        if not sink_node.resolved_symbol:
            return None

        # Buscar el nodo semántico correspondiente
        semantic_node = model.nodes_by_id.get(sink_node.node_id)
        if semantic_node:
            for arg in semantic_node.arguments:
                if arg.may_be_tainted:
                    return arg.position
        return None

    def _deduplicate_results(self, results: list[TaintResult]) -> list[TaintResult]:
        """
        Elimina resultados duplicados (mismo source+sink).
        Cuando hay duplicados, mantiene el de mayor confianza.
        """
        best: dict[tuple[str, str], TaintResult] = {}

        for result in results:
            key = (result.source_node_id, result.sink_node_id)
            if key not in best or result.confidence > best[key].confidence:
                best[key] = result

        return list(best.values())

    def _update_graph_taint_state(
        self,
        results: list[TaintResult],
        graph:   CSharpUnifiedGraph,
    ) -> None:
        """
        Actualiza el estado de taint de los nodos en el grafo
        basándose en los TaintResult obtenidos.

        Añade aristas TAINTS desde source hasta sink en el grafo.
        """
        for result in results:
            source_node = graph.get_node(result.source_node_id)
            sink_node   = graph.get_node(result.sink_node_id)

            if not source_node or not sink_node:
                continue

            # Añadir arista de taint directa source→sink
            taint_edge = CSharpEdge(
                edge_id=f"taint-{result.source_node_id[:8]}-{result.sink_node_id[:8]}",
                from_node_id=result.source_node_id,
                to_node_id=result.sink_node_id,
                kind=EdgeKind.TAINTS,
                label=f"taint:{result.source_taint_label}",
                taint_label=result.source_taint_label,
                confidence=result.confidence,
            )
            graph.add_edge(taint_edge)


# ─────────────────────────────────────────────────────────────────────────────
#  ANALIZADOR DE CAMINOS DE TAINT (para reportes)
# ─────────────────────────────────────────────────────────────────────────────

class TaintPathAnalyzer:
    """
    Analiza los caminos de taint de los TaintResult para generar
    información de contexto para los reportes.

    Produce:
      • Resúmenes legibles del camino de taint (para el reporte HTML)
      • Detección de patrones de vulnerabilidad específicos
      • Sugerencias de remediación basadas en el camino
    """

    def summarize_path(self, result: TaintResult) -> list[str]:
        """
        Genera un resumen legible del camino de taint.
        Retorna una lista de strings, uno por paso relevante.
        """
        if not result.taint_path:
            return [
                f"Fuente: {result.source_label} (L{result.source_line})",
                f"Destino: {result.sink_label} (L{result.sink_line})",
            ]

        summary: list[str] = []
        for i, step in enumerate(result.taint_path):
            file_short = step.file.split("/")[-1] if step.file else "?"
            prefix = "📍" if i == 0 else "⚠️" if i == len(result.taint_path) - 1 else "→"

            edge_desc = ""
            if step.edge_kind:
                edge_map = {
                    "flows_to":    "fluye hacia",
                    "aliases":     "alias de",
                    "assigned_to": "asignado a",
                    "captured_by": "capturado en lambda",
                    "returned_by": "retornado por",
                }
                edge_desc = f" [{edge_map.get(step.edge_kind, step.edge_kind)}]"

            if step.via_alias:
                edge_desc += f" (vía '{step.via_alias}')"

            conditional_note = " (condicional)" if step.is_conditional else ""
            summary.append(
                f"{prefix} L{step.line} — {step.label[:60]}"
                f"{edge_desc}{conditional_note} [{file_short}]"
            )

        return summary

    def detect_csharp_specific_patterns(
        self,
        result: TaintResult,
    ) -> list[str]:
        """
        Detecta patrones de vulnerabilidad específicos de C# en el camino.
        Retorna lista de patrones detectados (para metadata del reporte).
        """
        patterns: list[str] = []

        if not result.taint_path:
            return patterns

        path_kinds = [step.node_kind for step in result.taint_path]

        # Detectar SQL injection vía string interpolation
        if "STRING_INTERPOLATION" in path_kinds or "STRING_CONCAT" in path_kinds:
            patterns.append("sql_via_string_interpolation")

        # Detectar flujo async/await
        if result.is_async_flow or "AWAIT_EXPR" in path_kinds:
            patterns.append("async_taint_flow")

        # Detectar flujo vía LINQ
        if "LINQ_EXPRESSION" in path_kinds:
            patterns.append("linq_taint_flow")

        # Detectar flujo vía lambda/closure
        if "LAMBDA_CAPTURE" in path_kinds:
            patterns.append("lambda_capture_taint")

        # Detectar flujo vía colección
        if "COLLECTION_ITEM" in path_kinds:
            patterns.append("collection_taint_flow")

        # Detectar flujo condicional
        if result.has_partial_sanitizer:
            patterns.append("partial_sanitizer_bypass")

        # Detectar sink en loop (amplificación de impacto)
        if result.is_in_loop:
            patterns.append("sink_in_loop")

        # Detectar flujo inter-procedural
        if any(s.edge_kind == "returned_by" for s in result.taint_path):
            patterns.append("inter_procedural_taint")

        return patterns

    def get_remediation_context(
        self,
        result: TaintResult,
        patterns: list[str],
    ) -> str:
        """
        Genera contexto de remediación específico basado en el camino de taint.
        """
        parts: list[str] = []

        if "sql_via_string_interpolation" in patterns:
            parts.append(
                "El dato llega al sink vía string interpolation ($\"...\") o "
                "concatenación — usar FromSqlInterpolated (EF Core) o "
                "SqlParameter (ADO.NET) para parametrizar."
            )

        if "async_taint_flow" in patterns:
            parts.append(
                "El flujo de taint cruza operaciones async/await — "
                "el taint persiste a través de continuaciones. "
                "Sanitizar antes del await, no después."
            )

        if "linq_taint_flow" in patterns:
            parts.append(
                "El taint fluye a través de una expresión LINQ. "
                "Los valores dentro de .Where/.Select heredan el taint de la colección."
            )

        if "lambda_capture_taint" in patterns:
            parts.append(
                "Una variable tainted es capturada por una lambda/closure. "
                "El taint persiste en la closure incluso si el scope original termina."
            )

        if "sink_in_loop" in patterns:
            parts.append(
                "El sink está dentro de un loop — la vulnerabilidad puede "
                "ejecutarse múltiples veces, amplificando el impacto."
            )

        if "partial_sanitizer_bypass" in patterns and result.partial_sanitizer_symbol:
            san_name = result.partial_sanitizer_symbol.split(".")[-1]
            parts.append(
                f"Se detectó un sanitizador parcial ({san_name}) en el camino, "
                "pero no cubre todos los flujos de ejecución. "
                "Asegurar que el sanitizador esté en TODOS los caminos posibles."
            )

        if "inter_procedural_taint" in patterns:
            parts.append(
                "El taint cruza límites de método. "
                "Sanitizar los valores antes de retornarlos o pasarlos como argumentos."
            )

        return " ".join(parts) if parts else ""