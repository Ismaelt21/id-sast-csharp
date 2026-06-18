# =============================================================================
#  csharp-sast / core / parsers / ast_importer.py
# =============================================================================
#
#  IMPORTADOR DEL MODELO SEMÁNTICO DE ROSLYN
#  ──────────────────────────────────────────
#  Convierte el JSON exportado por el Roslyn Bridge al modelo interno
#  de Python usado por el resto del engine SAST.
#
#  RESPONSABILIDADES:
#    • Deserializar el JSON del bridge a dataclasses tipadas
#    • Construir índices de acceso rápido (por node_id, method_id, etc.)
#    • Normalizar y enriquecer los nodos (preclasificar sinks/sources)
#    • Validar la integridad del export (referencias cruzadas correctas)
#    • Exponer una interfaz limpia al resto del engine
#
#  SEPARACIÓN DE RESPONSABILIDADES:
#    Este módulo NO hace análisis SAST. Solo importa y normaliza.
#    El taint analysis y el pattern matching viven en analyzers/.
#
#  MODELO INTERNO VS EXPORT SCHEMA:
#    RoslynExportRoot (bridge JSON)  →  ParsedCSharpModel (Python interno)
#    SemanticNode (bridge JSON)      →  CSharpSemanticNode (Python interno)
#    MethodCfgExport (bridge JSON)   →  MethodCfg (Python interno)
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  DATACLASSES DEL MODELO INTERNO
#  Reflejan el ExportSchema.cs del bridge con tipos Python nativos.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalysisMetadata:
    files: list[str]
    language_version: str
    framework_detected: str | None
    nuget_references: list[str]
    compilation_errors: list[dict[str, Any]]
    analysis_timestamp: str
    bridge_version: str

    @property
    def has_compilation_errors(self) -> bool:
        return len(self.compilation_errors) > 0

    @property
    def framework(self) -> str:
        return self.framework_detected or "generic"


@dataclass
class ParameterInfo:
    name: str
    resolved_type: str
    position: int
    has_default: bool
    binding_attributes: list[str]

    @property
    def is_http_bound(self) -> bool:
        """True si el parámetro tiene atributos de binding HTTP explícitos."""
        http_attrs = {
            "FromQueryAttribute", "FromBodyAttribute", "FromRouteAttribute",
            "FromFormAttribute", "FromHeaderAttribute",
        }
        return bool(http_attrs & set(self.binding_attributes))

    @property
    def is_user_controlled(self) -> bool:
        """
        True si el parámetro puede contener input del atacante.
        Incluye parámetros simples de action methods sin atributo
        (ASP.NET Core los bindea automáticamente desde query string).
        """
        return self.is_http_bound or not self.binding_attributes


@dataclass
class MethodInfo:
    method_id: str
    name: str
    signature: str
    return_type: str
    is_async: bool
    is_static: bool
    accessibility: str
    parameters: list[ParameterInfo]
    attributes: list[str]
    file: str
    line_start: int
    line_end: int
    is_entry_point: bool
    containing_class_id: str

    @property
    def is_action_method(self) -> bool:
        """True si el método es un endpoint HTTP de ASP.NET."""
        action_attrs = {
            "HttpGetAttribute", "HttpPostAttribute", "HttpPutAttribute",
            "HttpDeleteAttribute", "HttpPatchAttribute", "RouteAttribute",
        }
        return bool(action_attrs & set(self.attributes))

    @property
    def is_wcf_operation(self) -> bool:
        return "OperationContractAttribute" in self.attributes

    @property
    def has_authorize(self) -> bool:
        return "AuthorizeAttribute" in self.attributes

    @property
    def allows_anonymous(self) -> bool:
        return "AllowAnonymousAttribute" in self.attributes


@dataclass
class ClassInfo:
    class_id: str
    name: str
    full_name: str
    kind: str  # "class" | "interface" | "struct" | "record"
    file: str
    line: int
    base_class: str | None
    interfaces: list[str]
    attributes: list[str]
    is_abstract: bool
    is_partial: bool
    methods: list[MethodInfo]

    @property
    def is_controller(self) -> bool:
        """True si la clase es un controller de ASP.NET."""
        controller_attrs = {"ApiControllerAttribute", "ControllerAttribute"}
        if controller_attrs & set(self.attributes):
            return True
        # Por convención: nombre termina en Controller y hereda de ControllerBase
        if self.name.endswith("Controller"):
            return True
        if self.base_class and "ControllerBase" in self.base_class:
            return True
        return False

    @property
    def is_wcf_service(self) -> bool:
        return "ServiceContractAttribute" in self.attributes


@dataclass
class ArgumentInfo:
    position: int
    text: str
    resolved_type: str | None
    is_literal: bool
    data_flow_origin: str  # "parameter" | "field" | "local_variable" | "return_value" | "literal" | "unknown"
    origin_parameter_name: str | None
    origin_node_id: str | None
    named_parameter: str | None

    @property
    def may_be_tainted(self) -> bool:
        """
        True si el argumento puede contener input del atacante.
        Los literales son siempre seguros.
        """
        if self.is_literal:
            return False
        return self.data_flow_origin in ("parameter", "return_value", "unknown")

    @property
    def is_from_parameter(self) -> bool:
        return self.data_flow_origin == "parameter"

    @property
    def is_from_return_value(self) -> bool:
        return self.data_flow_origin == "return_value"


@dataclass
class CSharpSemanticNode:
    """
    Nodo semántico de interés para el análisis SAST.
    Equivale al SemanticNode del ExportSchema.cs del bridge.
    """
    node_id: str
    kind: str  # "InvocationExpression" | "ObjectCreationExpression" | ...
    text: str
    file: str
    line: int
    column: int
    resolved_symbol: str | None
    resolved_type: str | None
    containing_method_id: str | None
    containing_class_id: str | None
    arguments: list[ArgumentInfo]
    is_async_call: bool
    is_in_try_block: bool
    parent_context: list[str]

    # Enriquecido por AstImporter tras la importación
    is_known_sink: bool = False
    is_known_source: bool = False
    is_known_sanitizer: bool = False

    @property
    def has_potentially_tainted_args(self) -> bool:
        return any(a.may_be_tainted for a in self.arguments)

    @property
    def tainted_arguments(self) -> list[ArgumentInfo]:
        return [a for a in self.arguments if a.may_be_tainted]

    @property
    def analysis_priority(self) -> int:
        """1=alta (sink con args sospechosos), 2=media, 3=baja."""
        if self.is_known_sink and self.has_potentially_tainted_args:
            return 1
        if self.is_known_sink or self.is_known_source:
            return 2
        return 3

    def __repr__(self) -> str:
        return (
            f"CSharpSemanticNode(kind={self.kind}, "
            f"symbol={self.resolved_symbol!r}, "
            f"line={self.line}, "
            f"sink={self.is_known_sink})"
        )


@dataclass
class CfgBlock:
    block_id: str
    kind: str  # "entry" | "exit" | "basic"
    node_ids: list[str]
    line_start: int
    line_end: int
    branch_condition: str | None
    is_exception_handler: bool


@dataclass
class CfgEdge:
    from_block_id: str
    to_block_id: str
    edge_kind: str  # "sequential" | "true_branch" | "false_branch" | "exception" | "return" | "throw"


@dataclass
class MethodCfg:
    method_id: str
    method_name: str
    blocks: list[CfgBlock]
    edges: list[CfgEdge]
    entry_block_id: str
    exit_block_ids: list[str]

    # Índices construidos por AstImporter
    blocks_by_id: dict[str, CfgBlock] = field(default_factory=dict, repr=False)


@dataclass
class AssignmentInfo:
    assignment_id: str
    target_name: str
    target_type: str | None
    source_node_id: str | None
    source_text: str
    is_literal: bool
    containing_method_id: str
    line: int


@dataclass
class ParameterFlow:
    method_id: str
    parameter_name: str
    parameter_type: str
    used_in_node_ids: list[str]
    assigned_to_ids: list[str]


@dataclass
class ReturnFlow:
    method_id: str
    returned_node_ids: list[str]
    return_type: str
    may_return_tainted: bool


@dataclass
class ExternalCall:
    node_id: str
    resolved_symbol: str
    assembly: str
    line: int
    file: str


@dataclass
class AttributeAnnotation:
    target_id: str
    target_kind: str
    attribute_name: str
    resolved_attribute: str | None
    arguments: list[str]


# ─────────────────────────────────────────────────────────────────────────────
#  MODELO INTERNO CONSOLIDADO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedCSharpModel:
    """
    Modelo interno completo del análisis Roslyn.
    Punto de entrada para todos los componentes del engine Python.

    Contiene los datos parseados del bridge MÁS índices de acceso
    rápido construidos durante la importación.
    """
    metadata: AnalysisMetadata
    classes: list[ClassInfo]
    semantic_nodes: list[CSharpSemanticNode]
    method_cfgs: list[MethodCfg]
    assignments: list[AssignmentInfo]
    parameter_flows: list[ParameterFlow]
    return_flows: list[ReturnFlow]
    external_calls: list[ExternalCall]
    attribute_annotations: list[AttributeAnnotation]

    # ── Índices de acceso rápido (construidos por AstImporter) ────────────────

    # node_id → SemanticNode
    nodes_by_id: dict[str, CSharpSemanticNode] = field(default_factory=dict, repr=False)

    # method_id → MethodInfo
    methods_by_id: dict[str, MethodInfo] = field(default_factory=dict, repr=False)

    # class_id → ClassInfo
    classes_by_id: dict[str, ClassInfo] = field(default_factory=dict, repr=False)

    # method_id → MethodCfg
    cfgs_by_method_id: dict[str, MethodCfg] = field(default_factory=dict, repr=False)

    # method_id → [SemanticNode] (nodos dentro de ese método)
    nodes_by_method: dict[str, list[CSharpSemanticNode]] = field(default_factory=dict, repr=False)

    # method_id → [AssignmentInfo]
    assignments_by_method: dict[str, list[AssignmentInfo]] = field(default_factory=dict, repr=False)

    # method_id → ParameterFlow
    param_flows_by_method: dict[str, list[ParameterFlow]] = field(default_factory=dict, repr=False)

    # ── Accesores de conveniencia ─────────────────────────────────────────────

    @property
    def sink_nodes(self) -> list[CSharpSemanticNode]:
        return [n for n in self.semantic_nodes if n.is_known_sink]

    @property
    def source_nodes(self) -> list[CSharpSemanticNode]:
        return [n for n in self.semantic_nodes if n.is_known_source]

    @property
    def high_priority_nodes(self) -> list[CSharpSemanticNode]:
        """Sinks con argumentos potencialmente tainted — máxima prioridad."""
        return [n for n in self.semantic_nodes if n.analysis_priority == 1]

    @property
    def controller_classes(self) -> list[ClassInfo]:
        return [c for c in self.classes if c.is_controller]

    @property
    def entry_point_methods(self) -> list[MethodInfo]:
        return [m for cls in self.classes for m in cls.methods if m.is_entry_point]

    @property
    def framework(self) -> str:
        return self.metadata.framework

    def get_method_for_node(self, node: CSharpSemanticNode) -> MethodInfo | None:
        if node.containing_method_id:
            return self.methods_by_id.get(node.containing_method_id)
        return None

    def get_class_for_node(self, node: CSharpSemanticNode) -> ClassInfo | None:
        method = self.get_method_for_node(node)
        if method:
            return self.classes_by_id.get(method.containing_class_id)
        return None

    def get_cfg_for_node(self, node: CSharpSemanticNode) -> MethodCfg | None:
        if node.containing_method_id:
            return self.cfgs_by_method_id.get(node.containing_method_id)
        return None

    def summary(self) -> str:
        return (
            f"ParsedCSharpModel("
            f"framework={self.framework}, "
            f"classes={len(self.classes)}, "
            f"nodes={len(self.semantic_nodes)}, "
            f"sinks={len(self.sink_nodes)}, "
            f"sources={len(self.source_nodes)}, "
            f"cfg_methods={len(self.method_cfgs)})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  IMPORTADOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class AstImporter:
    """
    Convierte el dict Python (JSON deserializado del bridge) al
    ParsedCSharpModel interno del engine.

    Uso:
        importer = AstImporter()
        model = importer.import_from_dict(roslyn_json_dict)
    """

    # Catálogo de sinks conocidos (prefijos) para preclasificación.
    # El engine Python tiene el catálogo completo en core/rules/;
    # esto es solo para acelerar el acceso sin cargar todas las reglas aquí.
    _SINK_PREFIXES = (
        # SQL Injection — solo constructores y métodos de ejecución
        "System.Data.SqlClient.SqlCommand",
        "Microsoft.Data.SqlClient.SqlCommand",
        "System.Data.SqlClient.SqlCommand..ctor",
        "System.Data.SqlClient.SqlCommand.ExecuteReader",
        "System.Data.SqlClient.SqlCommand.ExecuteNonQuery",
        "System.Data.SqlClient.SqlCommand.ExecuteScalar",
        "System.Data.SqlClient.SqlCommand.ExecuteXmlReader",
        "Microsoft.Data.SqlClient.SqlCommand..ctor",
        "Microsoft.Data.SqlClient.SqlCommand.ExecuteReader",
        "Microsoft.Data.SqlClient.SqlCommand.ExecuteNonQuery",
        "Microsoft.Data.SqlClient.SqlCommand.ExecuteScalar",
        "Microsoft.Data.SqlClient.SqlCommand.ExecuteXmlReader",
        "System.Data.OleDb.OleDbCommand",
        "System.Data.Odbc.OdbcCommand",
        "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw",
        "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw",
        "Dapper.SqlMapper.",
        # Command Injection
        "System.Diagnostics.Process.Start",
        # Path Traversal
        "System.IO.File.",
        # Deserialization
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
        "System.Web.Script.Serialization.JavaScriptSerializer.Deserialize",
        "Newtonsoft.Json.JsonConvert.DeserializeObject",
        # XXE
        "System.Xml.XmlDocument.Load",
        "System.Xml.XmlTextReader",
        # SSRF
        "System.Net.Http.HttpClient.",
        "System.Net.WebClient.",
        # Reflection
        "System.Reflection.Assembly.Load",
        "System.Activator.CreateInstance",
        # XSS
        "Microsoft.AspNetCore.Html.HtmlString",
        "System.Web.HtmlString",
    )

    _SOURCE_PREFIXES = (
        "Microsoft.AspNetCore.Http.IQueryCollection",
        "Microsoft.AspNetCore.Http.IFormCollection",
        "Microsoft.AspNetCore.Http.IHeaderDictionary",
        "Microsoft.AspNetCore.Http.HttpRequest.",
        "Microsoft.AspNetCore.Http.IQueryCollection[indexer]",
        "Microsoft.AspNetCore.Http.IFormCollection[indexer]", 
        "Microsoft.AspNetCore.Http.IHeaderDictionary[indexer]", 
        "Microsoft.AspNetCore.Routing.RouteData",
        "System.Web.HttpRequest.",
        "System.Console.ReadLine",
        "System.Environment.GetCommandLineArgs",
        "Microsoft.AspNetCore.Http.IFormFile.FileName",
    )

    _SANITIZER_PREFIXES = (
        "System.Data.SqlClient.SqlParameter",
        "Microsoft.Data.SqlClient.SqlParameter",
        "System.Data.SqlClient.SqlCommand.AddWithValue",
        "Microsoft.Data.SqlClient.SqlCommand.AddWithValue",
        "System.Data.SqlClient.SqlCommand.Parameters",
        "Microsoft.Data.SqlClient.SqlCommand.Parameters",
        "System.Net.WebUtility.HtmlEncode",
        "System.Web.HttpUtility.HtmlEncode",
        "System.Text.Encodings.Web.HtmlEncoder.Encode",
        "System.IO.Path.GetFileName",
        "System.IO.Path.GetFullPath",
        "System.Int32.TryParse",
        "System.Guid.TryParse",
    )

    def import_from_dict(self, data: dict[str, Any]) -> ParsedCSharpModel:
        """
        Importa el JSON del bridge al modelo interno.

        Args:
            data: Dict Python con el RoslynExportRoot (del JSON del bridge).

        Returns:
            ParsedCSharpModel completamente indexado y preclasificado.
        """
        t_start = __import__("time").monotonic()

        # ── 1. Metadata ───────────────────────────────────────────────────────
        metadata = self._import_metadata(data.get("metadata", {}))

        # ── 2. Clases y métodos ───────────────────────────────────────────────
        classes = self._import_classes(data.get("compilation_unit", {}).get("classes", []))

        # ── 3. Nodos semánticos ───────────────────────────────────────────────
        semantic_nodes = self._import_semantic_nodes(data.get("semantic_nodes", []))

        # ── 4. CFG ────────────────────────────────────────────────────────────
        method_cfgs = self._import_cfgs(data.get("control_flow", {}).get("methods", []))

        # ── 5. Data flow ──────────────────────────────────────────────────────
        df = data.get("data_flow", {})
        assignments = self._import_assignments(df.get("assignments", []))
        param_flows = self._import_parameter_flows(df.get("parameter_flows", []))
        return_flows = self._import_return_flows(df.get("return_flows", []))

        # ── 6. Symbols ────────────────────────────────────────────────────────
        sym = data.get("symbols", {})
        external_calls = self._import_external_calls(sym.get("external_calls", []))
        annotations = self._import_annotations(sym.get("attribute_annotations", []))

        # ── 7. Construir modelo y sus índices ─────────────────────────────────
        model = ParsedCSharpModel(
            metadata=metadata,
            classes=classes,
            semantic_nodes=semantic_nodes,
            method_cfgs=method_cfgs,
            assignments=assignments,
            parameter_flows=param_flows,
            return_flows=return_flows,
            external_calls=external_calls,
            attribute_annotations=annotations,
        )

        self._build_indexes(model)

        elapsed = (__import__("time").monotonic() - t_start) * 1000
        logger.info(
            "AstImporter: %s — importado en %.0f ms",
            model.summary(),
            elapsed,
        )

        return model

    # ─────────────────────────────────────────────────────────────────────────
    #  IMPORTADORES POR SECCIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _import_metadata(self, raw: dict[str, Any]) -> AnalysisMetadata:
        return AnalysisMetadata(
            files=raw.get("files", []),
            language_version=raw.get("language_version", "Latest"),
            framework_detected=raw.get("framework_detected"),
            nuget_references=raw.get("nuget_references", []),
            compilation_errors=raw.get("compilation_errors", []),
            analysis_timestamp=raw.get("analysis_timestamp", ""),
            bridge_version=raw.get("bridge_version", ""),
        )

    def _import_classes(self, raw_classes: list[dict]) -> list[ClassInfo]:
        classes = []
        for rc in raw_classes:
            methods = [self._import_method(rm) for rm in rc.get("methods", [])]
            classes.append(ClassInfo(
                class_id=rc["class_id"],
                name=rc["name"],
                full_name=rc["full_name"],
                kind=rc.get("kind", "class"),
                file=rc.get("file", ""),
                line=rc.get("line", 0),
                base_class=rc.get("base_class"),
                interfaces=rc.get("interfaces", []),
                attributes=rc.get("attributes", []),
                is_abstract=rc.get("is_abstract", False),
                is_partial=rc.get("is_partial", False),
                methods=methods,
            ))
        return classes

    def _import_method(self, rm: dict[str, Any]) -> MethodInfo:
        params = [
            ParameterInfo(
                name=rp["name"],
                resolved_type=rp["resolved_type"],
                position=rp["position"],
                has_default=rp.get("has_default", False),
                binding_attributes=rp.get("binding_attributes", []),
            )
            for rp in rm.get("parameters", [])
        ]
        return MethodInfo(
            method_id=rm["method_id"],
            name=rm["name"],
            signature=rm["signature"],
            return_type=rm["return_type"],
            is_async=rm.get("is_async", False),
            is_static=rm.get("is_static", False),
            accessibility=rm.get("accessibility", "private"),
            parameters=params,
            attributes=rm.get("attributes", []),
            file=rm.get("file", ""),
            line_start=rm.get("line_start", 0),
            line_end=rm.get("line_end", 0),
            is_entry_point=rm.get("is_entry_point", False),
            containing_class_id=rm["containing_class_id"],
        )

    def _import_semantic_nodes(self, raw_nodes: list[dict]) -> list[CSharpSemanticNode]:
        nodes = []
        for rn in raw_nodes:
            args = [self._import_argument(ra) for ra in rn.get("arguments", [])]
            symbol = self._normalize_symbol(rn.get("resolved_symbol"), rn.get("text", ""))
            node = CSharpSemanticNode(
                node_id=rn["node_id"],
                kind=rn["kind"],
                text=rn.get("text", ""),
                file=rn.get("file", ""),
                line=rn.get("line", 0),
                column=rn.get("column", 0),
                resolved_symbol=symbol,
                resolved_type=rn.get("resolved_type"),
                containing_method_id=rn.get("containing_method_id"),
                containing_class_id=rn.get("containing_class_id"),
                arguments=args,
                is_async_call=rn.get("is_async_call", False),
                is_in_try_block=rn.get("is_in_try_block", False),
                parent_context=rn.get("parent_context", []),
                is_known_sink=self._is_sink(symbol),
                is_known_source=self._is_source(symbol),
                is_known_sanitizer=self._is_sanitizer(symbol),
            )
            nodes.append(node)
        return nodes

    # ─────────────────────────────────────────────────────────────────────────────
    #  NORMALIZACIÓN DE SÍMBOLOS (fallback mientras el bridge emite nombres cortos)
    # ─────────────────────────────────────────────────────────────────────────────

    # Mapa de nombre corto → fully qualified name
    # Cubre los casos más frecuentes que el bridge devuelve sin namespace
    _SHORT_TO_FQN: dict[str, str] = {
        # System.IO
        "ReadAllText":    "System.IO.File.ReadAllText",
        "WriteAllText":   "System.IO.File.WriteAllText",
        "ReadAllBytes":   "System.IO.File.ReadAllBytes",
        "WriteAllBytes":  "System.IO.File.WriteAllBytes",
        "Delete":         "System.IO.File.Delete",
        "Combine":        "System.IO.Path.Combine",
        "GetFullPath":    "System.IO.Path.GetFullPath",
        "GetFileName":    "System.IO.Path.GetFileName",
        # System.Data.SqlClient
        "SqlCommand":     "System.Data.SqlClient.SqlCommand",
        "SqlConnection":  "System.Data.SqlClient.SqlConnection",
        "ExecuteNonQuery":"System.Data.SqlClient.SqlCommand.ExecuteNonQuery",
        "ExecuteReader":  "System.Data.SqlClient.SqlCommand.ExecuteReader",
        "ExecuteScalar":  "System.Data.SqlClient.SqlCommand.ExecuteScalar",
        # Microsoft.Data.SqlClient (preferido en .NET 8)
        # el bridge lo resuelve como SqlCommand también cuando no hay referencia
        # System.Diagnostics
        "Start":          "System.Diagnostics.Process.Start",
        # System.Console
        "ReadLine":       "System.Console.ReadLine",
        "ToString":       None,  # Ignorar — no es un sink/source relevante
        # IFormFile — source de path traversal
        "FileName":    "Microsoft.AspNetCore.Http.IFormFile.FileName",
    }

    def _normalize_symbol(self, symbol: str | None, node_text: str) -> str | None:
        """
        Intenta obtener el fully qualified name cuando el bridge devuelve
        solo el nombre corto del método (bug Problema 1).

        Estrategia:
        1. Si el símbolo ya tiene namespace (contiene '.') → devolver tal cual.
        2. Si está en el mapa _SHORT_TO_FQN → devolver el FQN conocido.
        3. Si no → devolver el símbolo original (puede ser correcto o inútil).
        """
        if not symbol:
            return symbol

        # ── NUEVO: quitar el prefijo global:: que emite Roslyn ──────────────
        if symbol.startswith("global::"):
            symbol = symbol[len("global::"):]


        # Ya tiene namespace → está bien
        if "." in symbol:
            return symbol

        fqn = self._SHORT_TO_FQN.get(symbol)

        # None explícito = símbolo que queremos descartar (ej: ToString)
        if fqn is None and symbol in self._SHORT_TO_FQN:
            return None

        if fqn:
            logger.debug(
                "AstImporter: símbolo normalizado '%s' → '%s'",
                symbol, fqn,
            )
            return fqn

        # Última heurística: buscar en el texto del nodo
        # ej: text = "File.ReadAllText(path)" → inferir System.IO.File
        if "File." in node_text:
            return f"System.IO.File.{symbol}"
        if "SqlCommand" in node_text or "cmd." in node_text.lower():
            return f"System.Data.SqlClient.SqlCommand.{symbol}"
        if "Process." in node_text:
            return f"System.Diagnostics.Process.{symbol}"

        return symbol

    def _import_argument(self, ra: dict[str, Any]) -> ArgumentInfo:
        return ArgumentInfo(
            position=ra.get("position", 0),
            text=ra.get("text", ""),
            resolved_type=ra.get("resolved_type"),
            is_literal=ra.get("is_literal", False),
            data_flow_origin=ra.get("data_flow_origin", "unknown"),
            origin_parameter_name=ra.get("origin_parameter_name"),
            origin_node_id=ra.get("origin_node_id"),
            named_parameter=ra.get("named_parameter"),
        )

    def _import_cfgs(self, raw_cfgs: list[dict]) -> list[MethodCfg]:
        cfgs = []
        for rc in raw_cfgs:
            blocks = [
                CfgBlock(
                    block_id=rb["block_id"],
                    kind=rb.get("kind", "basic"),
                    node_ids=rb.get("node_ids", []),
                    line_start=rb.get("line_start", 0),
                    line_end=rb.get("line_end", 0),
                    branch_condition=rb.get("branch_condition"),
                    is_exception_handler=rb.get("is_exception_handler", False),
                )
                for rb in rc.get("cfg_blocks", [])
            ]
            edges = [
                CfgEdge(
                    from_block_id=re["from_block_id"],
                    to_block_id=re["to_block_id"],
                    edge_kind=re.get("edge_kind", "sequential"),
                )
                for re in rc.get("cfg_edges", [])
            ]
            cfg = MethodCfg(
                method_id=rc["method_id"],
                method_name=rc.get("method_name", ""),
                blocks=blocks,
                edges=edges,
                entry_block_id=rc.get("entry_block_id", ""),
                exit_block_ids=rc.get("exit_block_ids", []),
                blocks_by_id={b.block_id: b for b in blocks},
            )
            cfgs.append(cfg)
        return cfgs

    def _import_assignments(self, raw: list[dict]) -> list[AssignmentInfo]:
        result = []
        for ra in raw:
            mid = ra.get("containing_method_id")
            if not mid:
                continue
            result.append(AssignmentInfo(
                assignment_id=ra["assignment_id"],
                target_name=ra.get("target_name", ""),
                target_type=ra.get("target_type"),
                source_node_id=ra.get("source_node_id"),
                source_text=ra.get("source_text", ""),
                is_literal=ra.get("is_literal", False),
                containing_method_id=mid,
                line=ra.get("line", 0),
            ))
        return result

    def _import_parameter_flows(self, raw: list[dict]) -> list[ParameterFlow]:
        return [
            ParameterFlow(
                method_id=rp["method_id"],
                parameter_name=rp["parameter_name"],
                parameter_type=rp.get("parameter_type", ""),
                used_in_node_ids=rp.get("used_in_node_ids", []),
                assigned_to_ids=rp.get("assigned_to_ids", []),
            )
            for rp in raw
        ]

    def _import_return_flows(self, raw: list[dict]) -> list[ReturnFlow]:
        return [
            ReturnFlow(
                method_id=rr["method_id"],
                returned_node_ids=rr.get("returned_node_ids", []),
                return_type=rr.get("return_type", "unknown"),
                may_return_tainted=rr.get("may_return_tainted", False),
            )
            for rr in raw
        ]

    def _import_external_calls(self, raw: list[dict]) -> list[ExternalCall]:
        return [
            ExternalCall(
                node_id=rc["node_id"],
                resolved_symbol=rc["resolved_symbol"],
                assembly=rc.get("assembly", ""),
                line=rc.get("line", 0),
                file=rc.get("file", ""),
            )
            for rc in raw
        ]

    def _import_annotations(self, raw: list[dict]) -> list[AttributeAnnotation]:
        return [
            AttributeAnnotation(
                target_id=ra["target_id"],
                target_kind=ra.get("target_kind", "method"),
                attribute_name=ra["attribute_name"],
                resolved_attribute=ra.get("resolved_attribute"),
                arguments=ra.get("arguments", []),
            )
            for ra in raw
        ]

    # ─────────────────────────────────────────────────────────────────────────
    #  CONSTRUCCIÓN DE ÍNDICES
    # ─────────────────────────────────────────────────────────────────────────

    def _build_indexes(self, model: ParsedCSharpModel) -> None:
        """Construye los índices de acceso rápido del modelo."""

        # Índice de nodos por ID
        model.nodes_by_id = {n.node_id: n for n in model.semantic_nodes}

        # Índice de clases y métodos
        for cls in model.classes:
            model.classes_by_id[cls.class_id] = cls
            for method in cls.methods:
                model.methods_by_id[method.method_id] = method

        # Índice de CFGs
        model.cfgs_by_method_id = {cfg.method_id: cfg for cfg in model.method_cfgs}

        # Nodos por método
        for node in model.semantic_nodes:
            if node.containing_method_id:
                model.nodes_by_method.setdefault(node.containing_method_id, []).append(node)

        # Asignaciones por método
        for asgn in model.assignments:
            model.assignments_by_method.setdefault(asgn.containing_method_id, []).append(asgn)

        # ParameterFlows por método
        for pf in model.parameter_flows:
            model.param_flows_by_method.setdefault(pf.method_id, []).append(pf)

        logger.debug(
            "Índices construidos: %d clases, %d métodos, %d nodos, %d CFGs.",
            len(model.classes_by_id),
            len(model.methods_by_id),
            len(model.nodes_by_id),
            len(model.cfgs_by_method_id),
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  CLASIFICACIÓN DE SÍMBOLOS
    # ─────────────────────────────────────────────────────────────────────────

    def _is_sink(self, symbol: str | None) -> bool:
        if not symbol:
            return False
        # Excluir explícitamente sanitizadores aunque hagan match con prefijo de sink
        if any(symbol.startswith(s) for s in self._SANITIZER_PREFIXES):
            return False
        return any(symbol.startswith(p) for p in self._SINK_PREFIXES)

    def _is_source(self, symbol: str | None) -> bool:
        if not symbol:
            return False
        return any(symbol.startswith(p) for p in self._SOURCE_PREFIXES)

    def _is_sanitizer(self, symbol: str | None) -> bool:
        if not symbol:
            return False
        return any(symbol.startswith(p) for p in self._SANITIZER_PREFIXES)