# =============================================================================
#  csharp-sast / core / analyzers / taint_analyzer.py
# =============================================================================
#
#  MOTOR PRINCIPAL DE TAINT ANALYSIS PARA C#
#  ──────────────────────────────────────────
#  Implementa análisis de flujo de datos contaminado (taint analysis) completo:
#
#  ALGORITMO GENERAL:
#    1. Identificar nodos SOURCE en el modelo (HttpRequest, RouteData, etc.)
#    2. Marcar esos nodos como "tainted" con su label (USER_INPUT, etc.)
#    3. Propagar el taint a través del DFG (asignaciones, alias, returns)
#    4. Detectar cuando el taint llega a un SINK conocido (SqlCommand, etc.)
#    5. Verificar si existe un SANITIZADOR en todos los caminos source→sink
#    6. Si no hay sanitizador → vulnerabilidad confirmada
#
#  FEATURES ESPECÍFICOS DE C#:
#    • Propagación a través de async/await
#    • Tracking de alias transitivos (var x = param; SqlCmd(x))
#    • Flujo inter-procedural (GetInput() retorna tainted → Sql(GetInput()))
#    • String interpolation: $"SELECT WHERE id={userId}" → SQL injection
#    • Colecciones: list.Add(userInput); SqlCmd(list[0]) → propagado
#    • Detección de sanitizadores en todos los caminos del CFG
#
#  INTEGRACIÓN CON EL MODELO:
#    Consume:
#      ParsedCSharpModel  (ast_importer.py)
#      ProjectCfgIndex    (cfg_builder.py)
#      ProjectDfgIndex    (dfg_builder.py)
#      FrameworkProfile   (framework_detector.py)
#      RuleSet            (rule_loader.py)
#
#    Produce:
#      list[TaintFinding] → consumido por vulnerability_classifier.py
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from core.parsers.ast_importer import (
    ArgumentInfo,
    CSharpSemanticNode,
    MethodInfo,
    ParsedCSharpModel,
)
from core.parsers.cfg_builder import CfgGraph, ProjectCfgIndex
from core.parsers.dfg_builder import (
    DfgNode,
    DfgNodeKind,
    DfgTaintPropagator,
    MethodDfg,
    ProjectDfgIndex,
)
from core.parsers.framework_detector import FrameworkProfile, FrameworkRuleMapper

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityKind(Enum):
    SQL_INJECTION             = "SQL_INJECTION"
    COMMAND_INJECTION         = "COMMAND_INJECTION"
    PATH_TRAVERSAL            = "PATH_TRAVERSAL"
    XXE                       = "XXE"
    INSECURE_DESERIALIZATION  = "INSECURE_DESERIALIZATION"
    SSRF                      = "SSRF"
    REFLECTION_ABUSE          = "REFLECTION_ABUSE"
    RAZOR_XSS                 = "RAZOR_XSS"
    XSS                       = "XSS"
    LOG_INJECTION             = "LOG_INJECTION"
    OPEN_REDIRECT             = "OPEN_REDIRECT"
    CSRF                      = "CSRF"   
    UNKNOWN                   = "UNKNOWN"


class TaintConfidence(Enum):
    """Nivel de confianza en la detección de taint."""
    CONFIRMED  = "confirmed"   # Source → Sink directo, sin ramas
    HIGH       = "high"        # Source → Sink a través de alias o assignments
    MEDIUM     = "medium"      # Source → Sink inter-procedural
    LOW        = "low"         # Heurística o flujo parcialmente rastreado


@dataclass
class TaintStep:
    """Un paso en el camino de propagación de taint."""
    node_id:     str
    kind:        str          # "source" | "assignment" | "alias" | "call" | "sink"
    label:       str          # Descripción del paso
    file:        str
    line:        int
    taint_label: str          # "USER_INPUT", "EXTERNAL_INPUT", etc.


@dataclass
class TaintFinding:
    """
    Resultado de un flujo de taint detectado.
    Es el output del TaintAnalyzer y el input del VulnerabilityClassifier.
    """
    # Identificación
    finding_id:      str
    vulnerability_kind: VulnerabilityKind
    confidence:      TaintConfidence

    # Nodo source (origen del taint)
    source_node_id:  str
    source_symbol:   str | None
    source_file:     str
    source_line:     int
    source_label:    str          # Descripción legible ("HttpRequest.QueryString['id']")
    taint_label:     str          # "USER_INPUT", "EXTERNAL_INPUT"

    # Nodo sink (destino vulnerable)
    sink_node_id:    str
    sink_symbol:     str | None
    sink_file:       str
    sink_line:       int
    sink_label:      str          # Descripción legible ("SqlCommand(query)")
    sink_arg_position: int | None  # Posición del argumento tainted en el sink

    # Contexto del método
    method_id:       str | None
    method_name:     str | None
    class_name:      str | None

    # Camino de propagación (para reportes)
    taint_path:      list[TaintStep] = field(default_factory=list)

    # Sanitizador (si se detectó pero no cubre todos los caminos)
    has_partial_sanitizer: bool = False
    sanitizer_symbol:      str | None = None

    # CFG reachability
    is_definitely_reachable: bool = True   # False = sólo posiblemente alcanzable
    is_in_loop:              bool = False   # Sink dentro de un loop

    # Metadatos para el classifier
    raw_evidence: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"TaintFinding({self.vulnerability_kind.value}, "
            f"conf={self.confidence.value}, "
            f"{self.source_file.split('/')[-1]}:{self.source_line}"
            f" → {self.sink_file.split('/')[-1]}:{self.sink_line})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  CATÁLOGO DE SINKS → TIPO DE VULNERABILIDAD
#  El engine Python mantiene este catálogo independientemente del bridge C#.
#  El bridge preclasifica; aquí hacemos la clasificación definitiva.
# ─────────────────────────────────────────────────────────────────────────────

_SINK_TO_VULN: list[tuple[str, VulnerabilityKind]] = [
    # SQL Injection
    ("System.Data.SqlClient.SqlCommand",                                      VulnerabilityKind.SQL_INJECTION),
    ("Microsoft.Data.SqlClient.SqlCommand",                                   VulnerabilityKind.SQL_INJECTION),
    ("System.Data.OleDb.OleDbCommand",                                        VulnerabilityKind.SQL_INJECTION),
    ("System.Data.Odbc.OdbcCommand",                                          VulnerabilityKind.SQL_INJECTION),
    ("Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw",VulnerabilityKind.SQL_INJECTION),
    ("Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw",VulnerabilityKind.SQL_INJECTION),
    ("Dapper.SqlMapper.Execute",                                              VulnerabilityKind.SQL_INJECTION),
    ("Dapper.SqlMapper.Query",                                                VulnerabilityKind.SQL_INJECTION),
    ("Dapper.SqlMapper.QueryAsync",                                           VulnerabilityKind.SQL_INJECTION),
    ("Dapper.SqlMapper.ExecuteAsync",                                         VulnerabilityKind.SQL_INJECTION),
    # Command Injection
    ("System.Diagnostics.Process.Start",                                      VulnerabilityKind.COMMAND_INJECTION),
    ("System.Diagnostics.ProcessStartInfo",                                   VulnerabilityKind.COMMAND_INJECTION),
    # Path Traversal
    ("System.IO.File.ReadAllText",                                            VulnerabilityKind.PATH_TRAVERSAL),
    ("System.IO.File.WriteAllText",                                           VulnerabilityKind.PATH_TRAVERSAL),
    ("System.IO.File.Open",                                                   VulnerabilityKind.PATH_TRAVERSAL),
    ("System.IO.File.Delete",                                                 VulnerabilityKind.PATH_TRAVERSAL),
    ("System.IO.File.ReadAllBytes",                                           VulnerabilityKind.PATH_TRAVERSAL),
    ("System.IO.FileStream",                                                  VulnerabilityKind.PATH_TRAVERSAL),
    ("System.IO.StreamReader",                                                VulnerabilityKind.PATH_TRAVERSAL),
    # Deserialization
    ("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize", VulnerabilityKind.INSECURE_DESERIALIZATION),
    ("System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize",     VulnerabilityKind.INSECURE_DESERIALIZATION),
    ("System.Web.Script.Serialization.JavaScriptSerializer.Deserialize",           VulnerabilityKind.INSECURE_DESERIALIZATION),
    ("Newtonsoft.Json.JsonConvert.DeserializeObject",                               VulnerabilityKind.INSECURE_DESERIALIZATION),
    ("System.Xml.Serialization.XmlSerializer.Deserialize",                         VulnerabilityKind.INSECURE_DESERIALIZATION),
    ("System.Runtime.Serialization.DataContractSerializer.ReadObject",             VulnerabilityKind.INSECURE_DESERIALIZATION),
    # XXE
    ("System.Xml.XmlDocument.Load",                                           VulnerabilityKind.XXE),
    ("System.Xml.XmlDocument.LoadXml",                                        VulnerabilityKind.XXE),
    ("System.Xml.XmlTextReader",                                              VulnerabilityKind.XXE),
    ("System.Xml.XmlReader.Create",                                           VulnerabilityKind.XXE),
    ("System.Xml.Linq.XDocument.Load",                                        VulnerabilityKind.XXE),
    # SSRF
    ("System.Net.Http.HttpClient.GetAsync",                                   VulnerabilityKind.SSRF),
    ("System.Net.Http.HttpClient.PostAsync",                                  VulnerabilityKind.SSRF),
    ("System.Net.Http.HttpClient.SendAsync",                                  VulnerabilityKind.SSRF),
    ("System.Net.WebClient.DownloadString",                                   VulnerabilityKind.SSRF),
    ("System.Net.WebRequest.Create",                                          VulnerabilityKind.SSRF),
    ("RestSharp.RestClient",                                                  VulnerabilityKind.SSRF),
    # Reflection Abuse
    ("System.Reflection.Assembly.Load",                                       VulnerabilityKind.REFLECTION_ABUSE),
    ("System.Reflection.Assembly.LoadFrom",                                   VulnerabilityKind.REFLECTION_ABUSE),
    ("System.Activator.CreateInstance",                                       VulnerabilityKind.REFLECTION_ABUSE),
    ("System.Type.GetType",                                                   VulnerabilityKind.REFLECTION_ABUSE),
    # Razor XSS
    ("Microsoft.AspNetCore.Html.HtmlString",                                  VulnerabilityKind.RAZOR_XSS),
    ("Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperExtensions.Raw",           VulnerabilityKind.RAZOR_XSS),
    ("System.Web.HtmlString",                                                 VulnerabilityKind.RAZOR_XSS),
    ("System.Web.Mvc.HtmlHelper.Raw",                                         VulnerabilityKind.RAZOR_XSS),
]

_SANITIZER_SYMBOLS: set[str] = {
    "System.Data.SqlClient.SqlParameter",
    "Microsoft.Data.SqlClient.SqlParameter",
    "System.Net.WebUtility.HtmlEncode",
    "System.Web.HttpUtility.HtmlEncode",
    "System.Text.Encodings.Web.HtmlEncoder.Encode",
    "Microsoft.Security.Application.Encoder.HtmlEncode",
    "System.Net.WebUtility.UrlEncode",
    "System.Web.HttpUtility.UrlEncode",
    "System.Uri.EscapeDataString",
    "System.IO.Path.GetFileName",
    "System.IO.Path.GetFullPath",
    "System.Int32.TryParse",
    "System.Guid.TryParse",
    "System.Int64.TryParse",
    "System.Double.TryParse",
    "System.Text.RegularExpressions.Regex.IsMatch",
    "System.IO.Path.GetFullPath",                    
    "System.String.StartsWith",                      
    "System.Data.SqlClient.SqlCommand.Parameters",      
    "Microsoft.Data.SqlClient.SqlCommand.Parameters", 
}


def _classify_sink(resolved_symbol: str | None) -> VulnerabilityKind:
    if not resolved_symbol:
        return VulnerabilityKind.UNKNOWN
    for prefix, kind in _SINK_TO_VULN:
        if resolved_symbol.startswith(prefix):
            return kind
    return VulnerabilityKind.UNKNOWN


def _is_sanitizer_symbol(resolved_symbol: str | None) -> bool:
    if not resolved_symbol:
        return False
    return any(resolved_symbol.startswith(s) for s in _SANITIZER_SYMBOLS)


# ─────────────────────────────────────────────────────────────────────────────
#  TAINT ANALYZER PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class TaintAnalyzer:
    """
    Motor principal de taint analysis para C#.

    Uso:
        analyzer = TaintAnalyzer(rules, cfg_index, dfg_index)
        findings = analyzer.analyze(model, framework_profile)
    """

    def __init__(
        self,
        rules: list[dict[str, Any]],
        cfg: ProjectCfgIndex,
        dfg: ProjectDfgIndex,
        framework: str | None = None,
    ) -> None:
        self._rules   = rules
        self._cfg     = cfg
        self._dfg     = dfg
        self._framework = framework
        self._propagator = DfgTaintPropagator()

        # Construir catálogo de fuentes desde las reglas cargadas
        self._source_taint_labels = self._build_source_labels(rules)

        # Contador para IDs de findings
        self._finding_counter = 0

    # ─────────────────────────────────────────────────────────────────────────
    #  MÉTODO PRINCIPAL
    # ─────────────────────────────────────────────────────────────────────────

    def analyze(self, model: ParsedCSharpModel) -> list[TaintFinding]:
        """
        Ejecuta el análisis de taint completo sobre el modelo.

        Estrategia de análisis:
          Fase A — Intra-procedural: analiza cada método por separado
                   usando su DFG y CFG.
          Fase B — Inter-procedural: conecta flujos entre métodos usando
                   los ReturnFlows del modelo.
          Fase C — String injection: detecta interpolaciones/concatenaciones
                   tainted que llegan a sinks.

        Returns:
            Lista de TaintFinding (puede estar vacía si no hay vulns).
        """
        all_findings: list[TaintFinding] = []
        total_methods = sum(len(cls.methods) for cls in model.classes)

        logger.info(
            "TaintAnalyzer: iniciando análisis de %d métodos, %d nodos semánticos.",
            total_methods,
            len(model.semantic_nodes),
        )

        # ── Fase A: Análisis intra-procedural ─────────────────────────────────
        for cls in model.classes:
            for method in cls.methods:
                try:
                    findings = self._analyze_method(method, cls.name, model)
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.warning(
                        "Error analizando método %s.%s: %s",
                        cls.name, method.name, exc,
                    )

        # ── Fase B: Análisis inter-procedural ─────────────────────────────────
        inter_findings = self._analyze_inter_procedural(model)
        all_findings.extend(inter_findings)

        # ── Fase C: String injection patterns ────────────────────────────────
        string_findings = self._analyze_string_injection(model)
        all_findings.extend(string_findings)

        # Deduplicar findings con el mismo source+sink
        deduplicated = self._deduplicate(all_findings)

        logger.info(
            "TaintAnalyzer: %d findings antes de dedup, %d después.",
            len(all_findings),
            len(deduplicated),
        )
        return deduplicated

    # ─────────────────────────────────────────────────────────────────────────
    #  FASE A: ANÁLISIS INTRA-PROCEDURAL
    # ─────────────────────────────────────────────────────────────────────────

    def _analyze_method(
        self,
        method: MethodInfo,
        class_name: str,
        model: ParsedCSharpModel,
    ) -> list[TaintFinding]:
        """Analiza el taint dentro de un método individual."""
        findings: list[TaintFinding] = []
        method_id = method.method_id

        # Obtener DFG del método
        method_dfg = self._dfg.get(method_id)
        if not method_dfg:
            return findings

        # Obtener CFG del método (puede ser None para métodos sin flujo de control)
        cfg = self._cfg.get(method_id)

        # ── 1. Identificar nodos source en los parámetros del método ──────────
        #    Los parámetros de action methods/entry points son el principal
        #    vector de entrada en ASP.NET Core.
        initial_tainted: set[str] = set()   # DfgNode IDs
        source_nodes: dict[str, str] = {}   # dfg_node_id → taint_label

        for param in method.parameters:
            param_dfg_id = f"param_{method_id}_{param.name}"
            if param_dfg_id not in method_dfg.nodes_by_id:
                continue

            # Determinar si el parámetro puede ser tainted
            taint_label = self._get_parameter_taint_label(
                param, method, model
            )
            if taint_label:
                initial_tainted.add(param_dfg_id)
                source_nodes[param_dfg_id] = taint_label

        # ── 2. Identificar nodos source directos en el cuerpo del método ─────
        #    Llamadas directas a sources: HttpContext.Request.Query["id"]
        semantic_nodes = model.nodes_by_method.get(method_id, [])
        for sn in semantic_nodes:
            if sn.is_known_source and not sn.is_known_sanitizer:
                sn_dfg_id = f"sn_{sn.node_id}"
                if sn_dfg_id in method_dfg.nodes_by_id:
                    taint_label = self._get_node_taint_label(sn)
                    initial_tainted.add(sn_dfg_id)
                    source_nodes[sn_dfg_id] = taint_label

        if not initial_tainted:
            return findings

        # ── 3. Identificar sanitizadores en el método ─────────────────────────
        sanitizer_dfg_ids: set[str] = set()
        for sn in semantic_nodes:
            if sn.is_known_sanitizer:
                sn_dfg_id = f"sn_{sn.node_id}"
                if sn_dfg_id in method_dfg.nodes_by_id:
                    sanitizer_dfg_ids.add(sn_dfg_id)

        # ── 4. Propagar taint en el DFG ───────────────────────────────────────
        tainted_nodes = self._propagator.propagate(
            method_dfg,
            initial_tainted_ids=initial_tainted,
            sanitizer_dfg_ids=sanitizer_dfg_ids,
        )

        # ── 5. Detectar sinks tainted ──────────────────────────────────────────
        tainted_sinks = self._propagator.get_tainted_sinks(method_dfg, tainted_nodes)

        for sink_dfg_node, taint_label in tainted_sinks:
            sn = sink_dfg_node.semantic_node
            if not sn:
                continue
            
            # ── FIX: si el sink tiene primer argumento literal → query parametrizada → seguro ──
            if sn.arguments and sn.arguments[0].is_literal:
                logger.debug(
                    "Sink ignorado — primer argumento es literal (query parametrizada): %s:%d",
                    sn.file.split("/")[-1], sn.line
                )
                continue

            # Encontrar el source original que originó este taint
            source_dfg_id = self._find_taint_origin(
                method_dfg, sink_dfg_node.node_id, source_nodes
            )
            if not source_dfg_id:
                continue

            source_dfg_node = method_dfg.nodes_by_id.get(source_dfg_id)
            if not source_dfg_node:
                continue

            # Verificar si hay sanitizador en TODOS los caminos CFG
            has_sanitizer_on_all_paths = self._check_cfg_sanitization(
                cfg, source_dfg_node, sink_dfg_node,
                sanitizer_dfg_ids, method_dfg
            )
            if has_sanitizer_on_all_paths:
                logger.debug(
                    "Sink sanitizado en todos los caminos: %s:%d",
                    sn.file.split("/")[-1], sn.line
                )
                continue

            # Detectar si el sink está en un loop (aumenta severidad)
            is_in_loop = self._is_in_loop(cfg, sn)

            # Construir el camino de taint
            taint_path = self._build_taint_path(
                method_dfg, source_dfg_id,
                sink_dfg_node.node_id, source_nodes,
                model
            )

            # Determinar el argumento tainted del sink
            tainted_arg_pos = self._find_tainted_argument_position(sn, tainted_nodes, method_dfg)

            # Determinar confianza
            confidence = self._calculate_confidence(
                source_dfg_node, sink_dfg_node, taint_path, cfg
            )

            # Determinar fuente legible
            source_label = self._build_source_label(source_dfg_node, source_nodes, model)
            sink_label   = self._build_sink_label(sn)
            vuln_kind    = _classify_sink(sn.resolved_symbol)

            finding = TaintFinding(
                finding_id=self._next_id(),
                vulnerability_kind=vuln_kind,
                confidence=confidence,
                source_node_id=source_dfg_id,
                source_symbol=sn.resolved_symbol,
                source_file=source_dfg_node.file,
                source_line=source_dfg_node.line,
                source_label=source_label,
                taint_label=source_nodes.get(source_dfg_id, "USER_INPUT"),
                sink_node_id=sink_dfg_node.node_id,
                sink_symbol=sn.resolved_symbol,
                sink_file=sn.file,
                sink_line=sn.line,
                sink_label=sink_label,
                sink_arg_position=tainted_arg_pos,
                method_id=method_id,
                method_name=method.name,
                class_name=class_name,
                taint_path=taint_path,
                has_partial_sanitizer=len(sanitizer_dfg_ids) > 0,
                sanitizer_symbol=self._get_sanitizer_symbol(sanitizer_dfg_ids, method_dfg),
                is_definitely_reachable=True,
                is_in_loop=is_in_loop,
                raw_evidence={
                    "source_kind": source_dfg_node.kind.name,
                    "sink_kind": "SEMANTIC_NODE",
                    "taint_path_length": len(taint_path),
                    "sanitizers_found": len(sanitizer_dfg_ids),
                },
            )
            findings.append(finding)

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  FASE B: ANÁLISIS INTER-PROCEDURAL
    # ─────────────────────────────────────────────────────────────────────────

    def _analyze_inter_procedural(self, model: ParsedCSharpModel) -> list[TaintFinding]:
        """
        Detecta flujos de taint que cruzan límites de métodos.

        Escenario:
          string GetId() { return Request.Query["id"]; }    // source
          void Save()    { var id = GetId(); Sql(id); }     // sink via call
        """
        findings: list[TaintFinding] = []

        # Construir mapa de ReturnFlows posiblemente tainted
        tainted_return_methods: set[str] = {
            rf.method_id
            for rf in model.return_flows
            if rf.may_return_tainted
        }

        if not tainted_return_methods:
            return findings

        # Para cada método que llama a un método con retorno tainted
        for cls in model.classes:
            for method in cls.methods:
                semantic_nodes = model.nodes_by_method.get(method.method_id, [])

                for sn in semantic_nodes:
                    if sn.kind != "InvocationExpression":
                        continue
                    if not sn.resolved_symbol:
                        continue

                    # Verificar si este nodo llama a un método con retorno tainted
                    called_method = self._find_called_method_by_symbol(
                        sn.resolved_symbol, tainted_return_methods, model
                    )
                    if not called_method:
                        continue

                    # Buscar sinks en el mismo método que usan el valor retornado
                    for sink_sn in semantic_nodes:
                        if not sink_sn.is_known_sink:
                            continue

                        # Verificar si el sink usa el resultado de la llamada
                        uses_return = any(
                            arg.origin_node_id == sn.node_id
                            or (arg.data_flow_origin == "return_value"
                                and abs(sink_sn.line - sn.line) <= 5)
                            for arg in sink_sn.arguments
                        )
                        if not uses_return:
                            continue

                        vuln_kind = _classify_sink(sink_sn.resolved_symbol)
                        finding = TaintFinding(
                            finding_id=self._next_id(),
                            vulnerability_kind=vuln_kind,
                            confidence=TaintConfidence.MEDIUM,
                            source_node_id=sn.node_id,
                            source_symbol=sn.resolved_symbol,
                            source_file=sn.file,
                            source_line=sn.line,
                            source_label=f"{called_method.name}() [retorna tainted]",
                            taint_label="USER_INPUT",
                            sink_node_id=sink_sn.node_id,
                            sink_symbol=sink_sn.resolved_symbol,
                            sink_file=sink_sn.file,
                            sink_line=sink_sn.line,
                            sink_label=self._build_sink_label(sink_sn),
                            sink_arg_position=None,
                            method_id=method.method_id,
                            method_name=method.name,
                            class_name=cls.name,
                            is_definitely_reachable=False,
                            raw_evidence={"type": "inter_procedural"},
                        )
                        findings.append(finding)

        logger.debug("Inter-procedural: %d findings.", len(findings))
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  FASE C: STRING INJECTION PATTERNS
    # ─────────────────────────────────────────────────────────────────────────

    _EXECUTE_METHODS_NO_ARGS: frozenset[str] = frozenset({
    "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar",
    "ExecuteReaderAsync", "ExecuteNonQueryAsync", "ExecuteScalarAsync",
    })

    def _analyze_string_injection(self, model: ParsedCSharpModel) -> list[TaintFinding]:
        """
        Detecta SQL/Command injection vía string interpolation y concatenación.

        Estos casos son detectados porque DfgExtractor.cs registra las
        asignaciones de tipo __interpolated_string y __string_concat
        con is_literal=false.

        Ejemplo detectado:
          var query = $"SELECT * WHERE id = {userId}";  → __interpolated_string
          SqlCommand(query)                              → sink tainted
        """
        findings: list[TaintFinding] = []

        for cls in model.classes:
            for method in cls.methods:
                assignments = model.assignments_by_method.get(method.method_id, [])

                # Encontrar asignaciones de string building tainted
                string_builds = [
                a for a in assignments
                if not a.is_literal
                and self._string_build_has_variable(a.source_text)
                and self._source_text_is_string_concat(a.source_text)
                ]

                if not string_builds:
                    continue

                semantic_nodes = model.nodes_by_method.get(method.method_id, [])
                sink_nodes = [sn for sn in semantic_nodes if sn.is_known_sink]

                for sb in string_builds:
                    for sink_sn in sink_nodes:
                        # El sink debe estar cerca de la interpolación (misma zona del método)
                        if abs(sink_sn.line - sb.line) > 10:
                            continue
                        
                         #Excluir Execute* sin argumentos
                        symbol_short = (sink_sn.resolved_symbol or "").split(".")[-1]
                        if not sink_sn.arguments and symbol_short in self._EXECUTE_METHODS_NO_ARGS:
                            continue

                        #Si el sink solo recibe literales o parámetros → seguro
                        if self._sink_uses_only_literal_or_parameterized(sink_sn):
                            continue
                        
                        # ── FIX: verificar que el string build realmente fluye al sink ──
                        # Si el sink recibe una variable cuyo nombre NO coincide con
                        # el target del string build, el taint no llega a ese sink.
                        if not self._string_build_flows_to_sink(sb, sink_sn):
                            continue

                        # Verificar que no hay sanitizador entre el string build y el sink
                        sanitizers_nearby = [
                            sn for sn in semantic_nodes
                            if sn.is_known_sanitizer
                            and sb.line <= sn.line <= sink_sn.line
                        ]
                        if sanitizers_nearby:
                            continue

                        vuln_kind = _classify_sink(sink_sn.resolved_symbol)
                        if vuln_kind not in (
                            VulnerabilityKind.SQL_INJECTION,
                            VulnerabilityKind.COMMAND_INJECTION,
                        ):
                            continue

                        findings.append(TaintFinding(
                            finding_id=self._next_id(),
                            vulnerability_kind=vuln_kind,
                            confidence=TaintConfidence.HIGH,
                            source_node_id=sb.assignment_id,
                            source_symbol=None,
                            source_file=sink_sn.file,
                            source_line=sb.line,
                            source_label=f"String building: {sb.source_text[:60]}",
                            taint_label="USER_INPUT",
                            sink_node_id=sink_sn.node_id,
                            sink_symbol=sink_sn.resolved_symbol,
                            sink_file=sink_sn.file,
                            sink_line=sink_sn.line,
                            sink_label=self._build_sink_label(sink_sn),
                            sink_arg_position=None,
                            method_id=method.method_id,
                            method_name=method.name,
                            class_name=cls.name,
                            is_definitely_reachable=True,
                            raw_evidence={"type": "string_injection", "source_text": sb.source_text},
                        ))

        logger.debug("String injection: %d findings.", len(findings))
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS DE TAINT
    # ─────────────────────────────────────────────────────────────────────────

    def _string_build_has_variable(self, source_text: str) -> bool:
        """
        True si la construcción de string contiene una variable real.
        
        Estrategia: verificar si el source_text del assignment tiene
        data_flow_origin != literal, o si contiene identificadores
        fuera de las comillas.
        """
        if not source_text:
            return False
        
        import re
        # ── FIX: solo quitar strings entre comillas DOBLES (C# no usa comillas simples para strings)
        # Las comillas simples en C# son chars o parte del contenido del string
        without_strings = re.sub(r'"(?:[^"\\]|\\.)*"', 'LITERAL', source_text)
        # NO quitar comillas simples — en C# son parte del contenido del string SQL
        
        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', without_strings)
        
        C_SHARP_KEYWORDS = {
            'LITERAL', 'var', 'string', 'int', 'bool', 'new', 'return',
            'null', 'true', 'false', 'using', 'this', 'if', 'else',
            'ToString', 'String',
        }
        real_identifiers = [t for t in tokens if t not in C_SHARP_KEYWORDS]
        
        return len(real_identifiers) > 0
    


    def _source_text_is_string_concat(self, source_text: str) -> bool:
        """
        True si el source_text es una concatenación/interpolación de string
        que incluye al menos un literal de string.
        
        Detecta:
        "SELECT ... '" + id + "'"     → True  (tiene literal + variable)
        $"SELECT WHERE id={userId}"   → True  (interpolación)
        new SqlConnection("...")      → False (constructor, no concat)
        Path.Combine("x", y)         → False (llamada a método)
        Request.Query["id"].ToString()→ False (acceso a propiedad)
        """
        stripped = source_text.strip()
        
        # Interpolación de string
        if stripped.startswith('$"') or stripped.startswith('$@"'):
            return True
        
        # Concatenación: contiene un string literal Y el operador +
        import re
        has_string_literal = bool(re.search(r'"[^"]*"', stripped))
        has_plus_operator  = '+' in stripped
        
        return has_string_literal and has_plus_operator

    def _sink_uses_only_literal_or_parameterized(self, sink_sn: CSharpSemanticNode) -> bool:
        # Sinks sin argumentos propios (ExecuteReader, ExecuteNonQuery, ExecuteScalar)
        # Solo son vulnerables si el SqlCommand que los llama recibió una query dinámica.
        # No podemos determinarlo aquí sin el grafo completo → no reportar desde
        # string_injection (el taint intra-procedural lo detectará si aplica).
        if not sink_sn.arguments:
            return True   # ← CAMBIAR False por True

        first_arg = sink_sn.arguments[0]
        if first_arg.is_literal:
            return True
        if first_arg.data_flow_origin == "literal":
            return True
        text = first_arg.text.strip()
        if text.startswith('"') or text.startswith("'") or text.startswith("@\""):
            return True
        return False

    def _string_build_flows_to_sink(self, sb: Any, sink_sn: CSharpSemanticNode) -> bool:
        """
        True si el string build realmente fluye al sink.
        
        Verifica que el primer argumento del sink referencia la variable
        producida por el string build (sb.target_name).
        
        Ejemplos:
        sb.target_name = 'sql'
        sink arg0.text = 'sql'           → True  (fluye)
        sink arg0.text = '"SELECT @id"'  → False (no fluye, es literal)
        
        sb.target_name = '__string_concat'
        sink arg0.text = 'sql'           → False (no fluye al cmd del Fixed)
        sink arg0.text = '__string_concat'→ True (caso raro)
        """
        if not sink_sn.arguments:
            return False
        
        first_arg = sink_sn.arguments[0]
        
        # Si el argumento es literal → no puede venir del string build
        if first_arg.is_literal:
            return False
        
        arg_text = first_arg.text.strip()
        target = sb.target_name.strip()
        
        # El argumento referencia directamente la variable del string build
        if arg_text == target:
            return True
        
        # El argumento contiene la variable (ej: "sql.Trim()" contiene "sql")
        if target != '__string_concat' and target in arg_text:
            return True
        
        # Para __string_concat: el argumento debe ser una variable que
        # recibe el resultado de la concatenación — buscar por data_flow_origin
        if target == '__string_concat':
            # Solo reportar si el argumento viene de una concatenación inline
            # (el texto del argumento contiene + y strings)
            import re
            has_literal = bool(re.search(r'"[^"]*"', arg_text))
            has_plus = '+' in arg_text
            if has_literal and has_plus:
                return True
            return False
        
        return False

    def _get_parameter_taint_label(
        self,
        param: Any,
        method: MethodInfo,
        model: ParsedCSharpModel,
    ) -> str | None:
        """
        Determina si un parámetro de método es una fuente de taint.
        Retorna el taint_label o None si el parámetro es seguro.
        """
        # Los parámetros de entry points (action methods) siempre son tainted
        if method.is_entry_point:
            return "USER_INPUT"

        # Parámetros con binding attributes HTTP son tainted
        if param.is_http_bound:
            return "USER_INPUT"

        # Parámetros de tipo string sin atributos en controllers son tainted
        # (ASP.NET Core model binding automático)
        class_info = model.classes_by_id.get(method.containing_class_id)
        if class_info and class_info.is_controller:
            if "String" in param.resolved_type or "string" in param.resolved_type:
                return "USER_INPUT"

        # Verificar si el framework dice que este parámetro es tainted
        for source_prefix, label in self._source_taint_labels.items():
            if source_prefix in param.resolved_type:
                return label
        
        # IFormFile siempre es tainted — su contenido y FileName vienen del cliente
        if "IFormFile" in param.resolved_type:
            return "USER_INPUT"

        # IFormFileCollection también
        if "IFormFileCollection" in param.resolved_type:
            return "USER_INPUT"

        return None
    

    def _get_node_taint_label(self, node: CSharpSemanticNode) -> str:
        """Determina el taint label de un nodo source."""
        if not node.resolved_symbol:
            return "USER_INPUT"

        for source_prefix, label in self._source_taint_labels.items():
            if node.resolved_symbol.startswith(source_prefix):
                return label

        return "USER_INPUT"

    def _find_taint_origin(
        self,
        method_dfg: MethodDfg,
        sink_dfg_id: str,
        source_nodes: dict[str, str],
    ) -> str | None:
        """
        Encuentra el nodo source original que originó el taint en el sink.
        Hace BFS inverso desde el sink hasta encontrar un nodo source.
        """
        import networkx as nx
        visited: set[str] = set()
        queue = [sink_dfg_id]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current in source_nodes:
                return current

            for pred in method_dfg.graph.predecessors(current):
                if pred not in visited:
                    queue.append(pred)

        return None

    def _check_cfg_sanitization(
        self,
        cfg: CfgGraph | None,
        source_dfg_node: DfgNode,
        sink_dfg_node: DfgNode,
        sanitizer_dfg_ids: set[str],
        method_dfg: MethodDfg,
    ) -> bool:
        """
        Verifica si TODOS los caminos del CFG desde source hasta sink
        pasan por al menos un sanitizador.

        Si el CFG no está disponible, usa heurística de líneas.
        """
        if not sanitizer_dfg_ids:
            return False

        # Obtener los semantic_node_ids de los sanitizadores
        sanitizer_semantic_ids: set[str] = set()
        for san_dfg_id in sanitizer_dfg_ids:
            san_node = method_dfg.nodes_by_id.get(san_dfg_id)
            if san_node and san_node.semantic_node:
                sanitizer_semantic_ids.add(san_node.semantic_node.node_id)

        if not cfg:
            # Heurística: si hay sanitizadores entre source y sink por número de línea
            source_line = source_dfg_node.line
            sink_line   = sink_dfg_node.line if sink_dfg_node.semantic_node else 0

            return any(
                method_dfg.nodes_by_id.get(sid) is not None
                and source_line <= (method_dfg.nodes_by_id[sid].line or 0) <= sink_line
                for sid in sanitizer_dfg_ids
            )

        # Usar el CFG para verificar en todos los caminos
        source_sn_id = (
            source_dfg_node.semantic_node.node_id
            if source_dfg_node.semantic_node else None
        )
        sink_sn_id = (
            sink_dfg_node.semantic_node.node_id
            if sink_dfg_node.semantic_node else None
        )

        if not source_sn_id or not sink_sn_id:
            return False

        source_block = cfg.get_block_for_node(source_sn_id)
        sink_block   = cfg.get_block_for_node(sink_sn_id)

        if not source_block or not sink_block:
            return False

        sanitizer_blocks = cfg.blocks_with_sanitizer(sanitizer_semantic_ids)
        if not sanitizer_blocks:
            return False

        paths = cfg.find_paths(source_block, sink_block, max_paths=20)
        if not paths:
            return False

        for path in paths:
            path_set = set(path)
            if not path_set & sanitizer_blocks:
                return False  # Camino sin sanitizador encontrado

        return True  # Todos los caminos tienen sanitizador

    def _is_in_loop(self, cfg: CfgGraph | None, sn: CSharpSemanticNode) -> bool:
        """True si el nodo sink está dentro de un loop (for, while, foreach)."""
        if not cfg:
            return False
        block_id = cfg.get_block_for_node(sn.node_id)
        if not block_id:
            return False
        loop_blocks = cfg.detect_loop_blocks()
        return block_id in loop_blocks

    def _build_taint_path(
        self,
        method_dfg: MethodDfg,
        source_dfg_id: str,
        sink_dfg_id: str,
        source_nodes: dict[str, str],
        model: ParsedCSharpModel,
    ) -> list[TaintStep]:
        """Construye el camino de taint desde source hasta sink."""
        steps: list[TaintStep] = []

        try:
            import networkx as nx
            paths = method_dfg.find_taint_paths(source_dfg_id, sink_dfg_id, max_paths=1)
            if not paths:
                return steps

            for dfg_id in paths[0]:
                node = method_dfg.nodes_by_id.get(dfg_id)
                if not node:
                    continue

                if dfg_id in source_nodes:
                    kind = "source"
                elif dfg_id == sink_dfg_id:
                    kind = "sink"
                elif node.kind in (DfgNodeKind.ASSIGNMENT, DfgNodeKind.STRING_BUILD):
                    kind = "assignment"
                elif node.kind == DfgNodeKind.LAMBDA_CAPTURE:
                    kind = "lambda_capture"
                else:
                    kind = "call"

                steps.append(TaintStep(
                    node_id=dfg_id,
                    kind=kind,
                    label=node.label[:80],
                    file=node.file,
                    line=node.line,
                    taint_label=source_nodes.get(dfg_id, "USER_INPUT"),
                ))
        except Exception as exc:
            logger.debug("No se pudo construir taint path: %s", exc)

        return steps

    def _find_tainted_argument_position(
        self,
        sink_sn: CSharpSemanticNode,
        tainted_nodes: dict[str, str],
        method_dfg: MethodDfg,
    ) -> int | None:
        """Encuentra la posición del argumento tainted en el sink."""
        for arg in sink_sn.arguments:
            if arg.is_literal:
                continue
            if arg.may_be_tainted:
                return arg.position
        return None

    def _calculate_confidence(
        self,
        source_dfg_node: DfgNode,
        sink_dfg_node: DfgNode,
        taint_path: list[TaintStep],
        cfg: CfgGraph | None,
    ) -> TaintConfidence:
        """Calcula el nivel de confianza del finding."""
        path_len = len(taint_path)

        if path_len <= 2:
            # Source → Sink directo → máxima confianza
            return TaintConfidence.CONFIRMED

        if path_len <= 4:
            return TaintConfidence.HIGH

        if source_dfg_node.kind == DfgNodeKind.PARAMETER:
            return TaintConfidence.HIGH

        return TaintConfidence.MEDIUM

    def _build_source_label(
        self,
        source_dfg_node: DfgNode,
        source_nodes: dict[str, str],
        model: ParsedCSharpModel,
    ) -> str:
        """Construye una etiqueta legible para el nodo source."""
        if source_dfg_node.kind == DfgNodeKind.PARAMETER:
            param_name = source_dfg_node.parameter_name or "param"
            method_name = (source_dfg_node.label or "").split(".")[0]
            return f"parámetro '{param_name}' de {method_name}()"

        if source_dfg_node.semantic_node:
            sn = source_dfg_node.semantic_node
            return f"{sn.text[:60]} [{sn.resolved_symbol or 'source'}]"

        return source_dfg_node.label[:80]

    def _build_sink_label(self, sink_sn: CSharpSemanticNode) -> str:
        """Construye una etiqueta legible para el nodo sink."""
        symbol = sink_sn.resolved_symbol or ""
        # Extraer solo el nombre del método del símbolo completo
        parts = symbol.split(".")
        short = parts[-1] if parts else symbol
        return f"{sink_sn.text[:50]} [{short}]"

    def _get_sanitizer_symbol(
        self,
        sanitizer_dfg_ids: set[str],
        method_dfg: MethodDfg,
    ) -> str | None:
        """Retorna el símbolo del primer sanitizador encontrado."""
        for sid in sanitizer_dfg_ids:
            node = method_dfg.nodes_by_id.get(sid)
            if node and node.semantic_node:
                return node.semantic_node.resolved_symbol
        return None

    def _find_called_method_by_symbol(
        self,
        resolved_symbol: str,
        tainted_method_ids: set[str],
        model: ParsedCSharpModel,
    ) -> MethodInfo | None:
        """Busca un método del proyecto cuyo símbolo coincide con la llamada."""
        for cls in model.classes:
            for method in cls.methods:
                if method.method_id in tainted_method_ids:
                    if method.name in resolved_symbol:
                        return method
        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  DEDUPLICACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _deduplicate(self, findings: list[TaintFinding]) -> list[TaintFinding]:
        """
        Elimina findings duplicados (mismo sink_node_id y source_node_id).
        Cuando hay duplicados, mantiene el de mayor confianza.
        """
        seen: dict[tuple[str, str], TaintFinding] = {}
        confidence_rank = {
            TaintConfidence.CONFIRMED: 0,
            TaintConfidence.HIGH:      1,
            TaintConfidence.MEDIUM:    2,
            TaintConfidence.LOW:       3,
        }

        for finding in findings:
            key = (finding.source_node_id, finding.sink_node_id)
            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                if confidence_rank[finding.confidence] < confidence_rank[existing.confidence]:
                    seen[key] = finding

        return list(seen.values())

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS INTERNOS
    # ─────────────────────────────────────────────────────────────────────────

    def _build_source_labels(self, rules: list[dict]) -> dict[str, str]:
        """Construye el mapa prefix→taint_label desde las reglas cargadas."""
        labels: dict[str, str] = {}
        for rule in rules:
            if rule.get("rule_type") == "source":
                symbol = rule.get("symbol", "")
                label  = rule.get("taint_label", "USER_INPUT")
                if symbol:
                    labels[symbol] = label
        return labels

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"taint-{self._finding_counter:04d}"