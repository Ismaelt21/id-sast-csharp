# =============================================================================
#  csharp-sast / core / analyzers / csharp_pattern_matcher.py
# =============================================================================
#
#  PATTERN MATCHER POR SÍMBOLO RESUELTO PARA C#
#  ──────────────────────────────────────────────
#  Detecta vulnerabilidades mediante match directo de resolved_symbol
#  contra el catálogo de sinks, sin necesidad de propagar taint.
#
#  DIFERENCIA CON EL TAINT ANALYZER:
#    TaintAnalyzer:        fuente → propagación → sink (flujo completo)
#    CSharpPatternMatcher: node.resolved_symbol == sink AND arg is not literal
#
#  CASOS QUE DETECTA:
#    1. Sink directo con argumento no literal:
#         SqlCommand(Request.Query["id"])        → SQL injection obvio
#    2. Constructores peligrosos con configuración insegura:
#         new XmlDocument() sin DtdProcessing=Prohibit → XXE
#         new BinaryFormatter()                 → Deserialization
#    3. Llamadas inherentemente peligrosas (sin importar args):
#         BinaryFormatter.Deserialize()         → siempre vulnerable si llega data
#    4. Atributos peligrosos:
#         [ValidateInput(false)]                → desactiva validación ASP.NET
#         TypeNameHandling.All en JsonConvert   → insecure deserialization
#
#  COMPLEMENTA AL TAINT ANALYZER:
#    • Detecta casos obvios rápidamente (sin construir grafos)
#    • Produce PatternFinding con menor confidence que TaintFinding
#    • El VulnerabilityClassifier los unifica en el reporte final
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from core.parsers.ast_importer import (
    AttributeAnnotation,
    CSharpSemanticNode,
    ClassInfo,
    MethodInfo,
    ParsedCSharpModel,
)
from core.analyzers.taint_analyzer import VulnerabilityKind, TaintConfidence

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  MODELO DE RESULTADO DEL PATTERN MATCHER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PatternFinding:
    """
    Vulnerabilidad detectada por match de patrón (sin taint flow completo).
    Tiene menor confianza que TaintFinding pero cubre más casos edge.
    """
    finding_id:         str
    vulnerability_kind: VulnerabilityKind
    confidence:         TaintConfidence
    pattern_id:         str        # ID de la regla de patrón que lo detectó
    pattern_name:       str        # Nombre legible de la regla

    # Ubicación
    file:               str
    line:               int
    column:             int
    code_snippet:       str        # Texto del nodo (truncado)

    # Símbolo
    resolved_symbol:    str | None
    matched_pattern:    str        # El prefijo del catálogo que hizo match

    # Contexto
    method_id:          str | None
    method_name:        str | None
    class_name:         str | None

    # Descripción para el reporte
    description:        str
    remediation:        str        # Cómo arreglarlo

    # Si el nodo tiene args tainted conocidos
    has_tainted_args:   bool = False
    tainted_arg_positions: list[int] = field(default_factory=list)

    # Evidence para el classifier
    raw_evidence: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"PatternFinding({self.pattern_name}, "
            f"{self.file.split('/')[-1]}:{self.line})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  CATÁLOGO DE PATRONES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SinkPattern:
    """Definición de un patrón de sink en el catálogo."""
    pattern_id:         str
    name:               str
    symbol_prefix:      str
    vulnerability_kind: VulnerabilityKind
    tainted_arg_positions: tuple[int, ...]  # Qué posiciones de argumento son el sink
    always_vulnerable:  bool                # True = vulnerable sin importar args
    confidence:         TaintConfidence
    description:        str
    remediation:        str
    cwe:                str
    cvss_base:          float


@dataclass(frozen=True)
class AttributePattern:
    """Patrón basado en atributos de clase/método."""
    pattern_id:         str
    name:               str
    attribute_name:     str
    vulnerability_kind: VulnerabilityKind
    confidence:         TaintConfidence
    description:        str
    remediation:        str
    cwe:                str


# Catálogo completo de patrones de sinks
SINK_PATTERNS: list[SinkPattern] = [
    # ── SQL Injection ─────────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="SQL-001",
        name="SqlCommand con query dinámica",
        symbol_prefix="System.Data.SqlClient.SqlCommand..ctor",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="SqlCommand construido con datos no parametrizados puede causar SQL Injection.",
        remediation="Usar SqlParameter para parametrizar la query: cmd.Parameters.AddWithValue('@id', id)",
        cwe="CWE-89",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="SQL-002",
        name="SqlCommand (Microsoft.Data)",
        symbol_prefix="Microsoft.Data.SqlClient.SqlCommand..ctor",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Microsoft.Data.SqlClient.SqlCommand con query dinámica.",
        remediation="Usar SqlParameter o procedimientos almacenados.",
        cwe="CWE-89",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="SQL-003",
        name="EF Core FromSqlRaw",
        symbol_prefix="Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(1,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="FromSqlRaw no parametrizado permite SQL Injection. Usar FromSqlInterpolated o FromSql con parámetros.",
        remediation="Reemplazar por FromSqlInterpolated($\"SELECT * WHERE id={id}\") o usar FromSql con DbParameter.",
        cwe="CWE-89",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="SQL-004",
        name="EF Core ExecuteSqlRaw",
        symbol_prefix="Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(1,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="ExecuteSqlRaw con SQL dinámico permite SQL Injection.",
        remediation="Usar ExecuteSqlInterpolated o pasar DbParameter explícito.",
        cwe="CWE-89",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="SQL-005",
        name="Dapper Execute",
        symbol_prefix="Dapper.SqlMapper.Execute",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(1,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Dapper.Execute con SQL dinámico es vulnerable a SQL Injection.",
        remediation="Usar parámetros anónimos: db.Execute(\"SELECT * WHERE @id\", new { id = id })",
        cwe="CWE-89",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="SQL-006",
        name="Dapper Query",
        symbol_prefix="Dapper.SqlMapper.Query",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(1,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Dapper.Query con SQL dinámico sin parametrizar.",
        remediation="Parametrizar el SQL con objeto anónimo como segundo argumento.",
        cwe="CWE-89",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="SQL-007",
        name="OleDb Command",
        symbol_prefix="System.Data.OleDb.OleDbCommand",
        vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="OleDbCommand con query dinámica es vulnerable a SQL Injection.",
        remediation="Usar OleDbParameter para parametrizar.",
        cwe="CWE-89",
        cvss_base=9.8,
    ),

    # ── Command Injection ────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="CMD-001",
        name="Process.Start con args dinámicos",
        symbol_prefix="System.Diagnostics.Process.Start",
        vulnerability_kind=VulnerabilityKind.COMMAND_INJECTION,
        tainted_arg_positions=(0, 1),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Process.Start con argumentos controlados por el usuario permite Command Injection.",
        remediation="Validar y sanear el input. Usar una whitelist de comandos permitidos. Nunca pasar input crudo como argumento.",
        cwe="CWE-78",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="CMD-002",
        name="ProcessStartInfo con FileName dinámico",
        symbol_prefix="System.Diagnostics.ProcessStartInfo..ctor",
        vulnerability_kind=VulnerabilityKind.COMMAND_INJECTION,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="ProcessStartInfo construido con FileName o Arguments dinámicos.",
        remediation="Separar FileName de Arguments. Nunca incluir input de usuario en FileName.",
        cwe="CWE-78",
        cvss_base=9.8,
    ),

    # ── Path Traversal ────────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="PATH-001",
        name="File.ReadAllText con ruta dinámica",
        symbol_prefix="System.IO.File.ReadAllText",
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="File.ReadAllText con ruta controlada por el usuario permite Path Traversal.",
        remediation="Usar Path.GetFileName() para eliminar componentes de directorio. Validar contra un directorio base.",
        cwe="CWE-22",
        cvss_base=7.5,
    ),
    SinkPattern(
        pattern_id="PATH-002",
        name="File.Open con ruta dinámica",
        symbol_prefix="System.IO.File.Open",
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="File.Open con ruta dinámica sin validación.",
        remediation="Combinar con Path.GetFullPath() y verificar que el path resultante esté dentro del directorio permitido.",
        cwe="CWE-22",
        cvss_base=7.5,
    ),
    SinkPattern(
        pattern_id="PATH-003",
        name="FileStream con ruta dinámica",
        symbol_prefix="System.IO.FileStream..ctor",
        vulnerability_kind=VulnerabilityKind.PATH_TRAVERSAL,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="FileStream construido con ruta controlada por el usuario.",
        remediation="Validar el path con Path.GetFullPath() y verificar contra el directorio base permitido.",
        cwe="CWE-22",
        cvss_base=7.5,
    ),

    # ── Insecure Deserialization ──────────────────────────────────────────────
    SinkPattern(
        pattern_id="DESER-001",
        name="BinaryFormatter.Deserialize",
        symbol_prefix="System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",
        vulnerability_kind=VulnerabilityKind.INSECURE_DESERIALIZATION,
        tainted_arg_positions=(0,),
        always_vulnerable=True,  # BinaryFormatter es inherentemente inseguro
        confidence=TaintConfidence.CONFIRMED,
        description="BinaryFormatter.Deserialize es inherentemente inseguro y permite Remote Code Execution. Obsoleto desde .NET 5.",
        remediation="Reemplazar por System.Text.Json.JsonSerializer o XmlSerializer con tipos conocidos. BinaryFormatter debe eliminarse del código.",
        cwe="CWE-502",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="DESER-002",
        name="JavaScriptSerializer.Deserialize",
        symbol_prefix="System.Web.Script.Serialization.JavaScriptSerializer.Deserialize",
        vulnerability_kind=VulnerabilityKind.INSECURE_DESERIALIZATION,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="JavaScriptSerializer con TypeResolver puede permitir deserialización de tipos arbitrarios.",
        remediation="Usar System.Text.Json.JsonSerializer que es seguro por defecto.",
        cwe="CWE-502",
        cvss_base=8.1,
    ),
    SinkPattern(
        pattern_id="DESER-003",
        name="JsonConvert.DeserializeObject",
        symbol_prefix="Newtonsoft.Json.JsonConvert.DeserializeObject",
        vulnerability_kind=VulnerabilityKind.INSECURE_DESERIALIZATION,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.MEDIUM,  # Solo si TypeNameHandling != None
        description="Newtonsoft.Json con TypeNameHandling != None puede deserializar tipos arbitrarios.",
        remediation="Verificar que TypeNameHandling = None (default). Si se necesita polimorfismo, usar JsonDerivedType.",
        cwe="CWE-502",
        cvss_base=8.1,
    ),

    # ── XXE ───────────────────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="XXE-001",
        name="XmlDocument.Load sin DtdProcessing=Prohibit",
        symbol_prefix="System.Xml.XmlDocument.Load",
        vulnerability_kind=VulnerabilityKind.XXE,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="XmlDocument.Load sin configurar XmlResolver=null y DtdProcessing=Prohibit es vulnerable a XXE.",
        remediation="Configurar: xmlDoc.XmlResolver = null; o usar XmlReader con XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }",
        cwe="CWE-611",
        cvss_base=7.5,
    ),
    SinkPattern(
        pattern_id="XXE-002",
        name="XmlDocument.LoadXml",
        symbol_prefix="System.Xml.XmlDocument.LoadXml",
        vulnerability_kind=VulnerabilityKind.XXE,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="XmlDocument.LoadXml con data no confiable es vulnerable a XXE.",
        remediation="Configurar XmlResolver=null antes de llamar LoadXml.",
        cwe="CWE-611",
        cvss_base=7.5,
    ),

    # ── SSRF ──────────────────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="SSRF-001",
        name="HttpClient.GetAsync con URL dinámica",
        symbol_prefix="System.Net.Http.HttpClient.GetAsync",
        vulnerability_kind=VulnerabilityKind.SSRF,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="HttpClient.GetAsync con URL controlada por el usuario permite SSRF.",
        remediation="Validar el host destino contra una whitelist. Nunca usar URLs construidas desde input del usuario.",
        cwe="CWE-918",
        cvss_base=8.6,
    ),
    SinkPattern(
        pattern_id="SSRF-002",
        name="HttpClient.PostAsync con URL dinámica",
        symbol_prefix="System.Net.Http.HttpClient.PostAsync",
        vulnerability_kind=VulnerabilityKind.SSRF,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="HttpClient.PostAsync con URL dinámica permite SSRF.",
        remediation="Whitelist de dominios permitidos. Deshabilitar redirecciones automáticas.",
        cwe="CWE-918",
        cvss_base=8.6,
    ),
    SinkPattern(
        pattern_id="SSRF-003",
        name="WebRequest.Create con URL dinámica",
        symbol_prefix="System.Net.WebRequest.Create",
        vulnerability_kind=VulnerabilityKind.SSRF,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="WebRequest.Create con URL controlada por usuario permite SSRF.",
        remediation="Validar la URL. Usar HttpClient con handler que verifique el host destino.",
        cwe="CWE-918",
        cvss_base=8.6,
    ),

    # ── Reflection Abuse ──────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="REFLECT-001",
        name="Assembly.Load con nombre dinámico",
        symbol_prefix="System.Reflection.Assembly.Load",
        vulnerability_kind=VulnerabilityKind.REFLECTION_ABUSE,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Assembly.Load con nombre controlado por el usuario puede cargar código arbitrario.",
        remediation="Usar una whitelist de assemblies permitidos. Nunca cargar assemblies con nombres de input del usuario.",
        cwe="CWE-470",
        cvss_base=9.8,
    ),
    SinkPattern(
        pattern_id="REFLECT-002",
        name="Activator.CreateInstance con tipo dinámico",
        symbol_prefix="System.Activator.CreateInstance",
        vulnerability_kind=VulnerabilityKind.REFLECTION_ABUSE,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Activator.CreateInstance con tipo controlado por el usuario permite instanciar clases arbitrarias.",
        remediation="Usar una whitelist de tipos permitidos. Nunca instanciar tipos derivados de input del usuario.",
        cwe="CWE-470",
        cvss_base=8.1,
    ),
    SinkPattern(
        pattern_id="REFLECT-003",
        name="Type.GetType con nombre dinámico",
        symbol_prefix="System.Type.GetType",
        vulnerability_kind=VulnerabilityKind.REFLECTION_ABUSE,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.MEDIUM,
        description="Type.GetType con nombre de tipo dinámico puede exponer clases sensibles.",
        remediation="Validar el nombre del tipo contra una whitelist antes de resolver.",
        cwe="CWE-470",
        cvss_base=6.5,
    ),

    # ── Razor XSS ─────────────────────────────────────────────────────────────
    SinkPattern(
        pattern_id="XSS-001",
        name="HtmlString con contenido dinámico",
        symbol_prefix="Microsoft.AspNetCore.Html.HtmlString..ctor",
        vulnerability_kind=VulnerabilityKind.RAZOR_XSS,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="HtmlString marca contenido como HTML seguro, bypasseando el encoding automático de Razor. Con input del usuario es XSS.",
        remediation="Usar HtmlEncoder.Encode() antes de crear HtmlString, o no usar HtmlString con input del usuario.",
        cwe="CWE-79",
        cvss_base=6.1,
    ),
    SinkPattern(
        pattern_id="XSS-002",
        name="Html.Raw con contenido dinámico",
        symbol_prefix="Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperExtensions.Raw",
        vulnerability_kind=VulnerabilityKind.RAZOR_XSS,
        tainted_arg_positions=(0,),
        always_vulnerable=False,
        confidence=TaintConfidence.HIGH,
        description="Html.Raw() bypasea el encoding de Razor. Con datos del usuario produce XSS.",
        remediation="No usar Html.Raw() con input del usuario. Usar @Html.Encode() o confiar en el encoding automático de Razor (@variable).",
        cwe="CWE-79",
        cvss_base=6.1,
    ),
]

# Catálogo de patrones de atributos peligrosos
ATTRIBUTE_PATTERNS: list[AttributePattern] = [
    AttributePattern(
        pattern_id="ATTR-001",
        name="ValidateInput(false) desactiva validación",
        attribute_name="ValidateInputAttribute",
        vulnerability_kind=VulnerabilityKind.XSS,
        confidence=TaintConfidence.MEDIUM,
        description="[ValidateInput(false)] desactiva la validación de request de ASP.NET MVC, permitiendo HTML/script en el input.",
        remediation="Eliminar [ValidateInput(false)] o usar [AllowHtml] solo en propiedades específicas con encoding explícito.",
        cwe="CWE-79",
    ),
    AttributePattern(
        pattern_id="ATTR-002",
        name="AllowHtml sin encoding explícito",
        attribute_name="AllowHtmlAttribute",
        vulnerability_kind=VulnerabilityKind.XSS,
        confidence=TaintConfidence.LOW,
        description="[AllowHtml] permite HTML sin encoding. Si se renderiza sin sanitizar produce XSS.",
        remediation="Sanitizar con HtmlSanitizer antes de almacenar/renderizar contenido marcado con [AllowHtml].",
        cwe="CWE-79",
    ),
]

# Mapa rápido: symbol_prefix → SinkPattern
_PATTERN_INDEX: dict[str, SinkPattern] = {
    p.symbol_prefix: p for p in SINK_PATTERNS
}


# ─────────────────────────────────────────────────────────────────────────────
#  MATCHER PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class CSharpPatternMatcher:
    """
    Detecta vulnerabilidades mediante match directo de símbolos resueltos.

    Uso:
        matcher = CSharpPatternMatcher(rules)
        findings = matcher.match(model)
    """

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self._rules = rules
        # Combinar el catálogo estático con reglas cargadas dinámicamente
        self._extra_patterns = self._load_extra_patterns(rules)

    def match(self, model: ParsedCSharpModel) -> list[PatternFinding]:
        """
        Ejecuta el matching de patrones sobre todos los nodos semánticos.

        Returns:
            Lista de PatternFinding con vulnerabilidades detectadas por patrón.
        """
        findings: list[PatternFinding] = []
        counter = 0

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue

            # Buscar el patrón que hace match con el símbolo
            pattern = self._find_matching_pattern(sn.resolved_symbol)
            if not pattern:
                continue
            
            # ── FIX: pasar el modelo para verificar sanitización en contexto ──
            if not self._should_report(sn, pattern, model):
                continue
            
            # Obtener contexto del método y clase
            method = model.get_method_for_node(sn)
            cls    = model.get_class_for_node(sn)

            counter += 1
            finding = PatternFinding(
                finding_id=f"pattern-{counter:04d}",
                vulnerability_kind=pattern.vulnerability_kind,
                confidence=self._adjust_confidence(sn, pattern),
                pattern_id=pattern.pattern_id,
                pattern_name=pattern.name,
                file=sn.file,
                line=sn.line,
                column=sn.column,
                code_snippet=sn.text[:120],
                resolved_symbol=sn.resolved_symbol,
                matched_pattern=pattern.symbol_prefix,
                method_id=method.method_id if method else None,
                method_name=method.name if method else None,
                class_name=cls.name if cls else None,
                description=pattern.description,
                remediation=pattern.remediation,
                has_tainted_args=sn.has_potentially_tainted_args,
                tainted_arg_positions=[
                    a.position for a in sn.arguments
                    if not a.is_literal and a.may_be_tainted
                ],
                raw_evidence={
                    "resolved_symbol": sn.resolved_symbol,
                    "cwe": pattern.cwe,
                    "cvss_base": pattern.cvss_base,
                    "always_vulnerable": pattern.always_vulnerable,
                    "is_in_try": sn.is_in_try_block,
                },
            )
            findings.append(finding)

        # También analizar atributos peligrosos
        attr_findings = self._match_attribute_patterns(model, counter)
        findings.extend(attr_findings)

        logger.info(
            "PatternMatcher: %d findings en %d nodos semánticos.",
            len(findings),
            len(model.semantic_nodes),
        )
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  MATCH DE PATRONES DE SINK
    # ─────────────────────────────────────────────────────────────────────────

    def _find_matching_pattern(self, resolved_symbol: str) -> SinkPattern | None:
        """Busca el patrón que hace match con el símbolo resuelto."""
        # Primero buscar match exacto
        if resolved_symbol in _PATTERN_INDEX:
            return _PATTERN_INDEX[resolved_symbol]

        # Luego buscar por prefijo (para sobrecargas)
        for prefix, pattern in _PATTERN_INDEX.items():
            if resolved_symbol.startswith(prefix):
                return pattern

        # Buscar en patrones extra cargados desde reglas
        for prefix, pattern in self._extra_patterns.items():
            if resolved_symbol.startswith(prefix):
                return pattern

        return None

    def _should_report(self, sn: CSharpSemanticNode, pattern: SinkPattern, model: ParsedCSharpModel | None = None) -> bool:
        """
        Determina si el match debe reportarse según las condiciones del patrón.

        Reglas:
          - Si always_vulnerable=True → siempre reportar (BinaryFormatter)
          - Si todos los argumentos en tainted_arg_positions son literales → no reportar
          - Si el nodo está en try y el patrón no es crítico → reducir confianza
        """
        if pattern.always_vulnerable:
            return True

        # Verificar que al menos un argumento en las posiciones del sink no es literal
        if pattern.tainted_arg_positions:
            for pos in pattern.tainted_arg_positions:
                if pos < len(sn.arguments):
                    arg = sn.arguments[pos]
                    if not arg.is_literal:
                        if (pattern.vulnerability_kind == VulnerabilityKind.PATH_TRAVERSAL
                                and model is not None):
                            if self._path_is_sanitized_in_method(sn, model):
                                return False
                        if (pattern.vulnerability_kind == VulnerabilityKind.SSRF
                                and model is not None):
                            if self._ssrf_host_whitelist_in_method(sn, model):
                                return False
                        return True
            return False
        # Si no hay posiciones definidas, reportar si tiene args no literales
        return sn.has_potentially_tainted_args or not sn.arguments

    def _path_is_sanitized_in_method(
        self,
        sink_sn: CSharpSemanticNode,
        model: ParsedCSharpModel,
    ) -> bool:
        """
        Verifica si en el mismo método existe un patrón seguro de path handling.

        Cubre dos variantes válidas:
          1. `GetFileName` + `GetFullPath`/`StartsWith`
          2. `GetFullPath(Path.Combine(...))` + `StartsWith`

        La segunda variante es la que usa el sample fijo de path traversal.
        """
        if not sink_sn.containing_method_id:
            return False

        nodes_in_method = model.nodes_by_method.get(sink_sn.containing_method_id, [])

        has_get_filename = False
        has_starts_with  = False
        has_get_fullpath = False

        for n in nodes_in_method:
            symbol = (n.resolved_symbol or "").lower()
            text   = (n.text or "").lower()

            if "path.getfilename" in symbol or "getfilename" in text:
                has_get_filename = True
            if "path.getfullpath" in symbol or "getfullpath" in text:
                has_get_fullpath = True
            if "startswith" in text:
                has_starts_with = True

        # Patrón seguro:
        # - GetFileName + (GetFullPath o StartsWith)
        # - o bien GetFullPath + StartsWith aunque no exista GetFileName
        if has_get_filename and (has_get_fullpath or has_starts_with):
            return True

        return has_get_fullpath and has_starts_with

    def _ssrf_host_whitelist_in_method(
        self,
        sink_sn: CSharpSemanticNode,
        model: ParsedCSharpModel,
    ) -> bool:
        """
        Detecta el patrón seguro "host whitelist" para evitar SSRF falsos positivos.

        Se considera mitigado cuando el método contiene una comparación contra
        una whitelist de hosts usando `Host`, `Contains` o `IndexOf`.
        """
        if not sink_sn.containing_method_id:
            return False

        nodes_in_method = model.nodes_by_method.get(sink_sn.containing_method_id, [])

        has_host_check = False
        has_whitelist_hint = False

        for n in nodes_in_method:
            symbol = (n.resolved_symbol or "").lower()
            text = (n.text or "").lower()

            if ".host" in text and ("contains(" in text or "indexof(" in text):
                has_host_check = True
            if (
                "whitelist" in text
                or "_whitelist" in text
                or "allowedhost" in text
                or "allowedhosts" in text
            ):
                has_whitelist_hint = True
            if "array.indexof" in text and ".host" in text:
                has_host_check = True
            if "contains" in symbol and ".host" in text:
                has_host_check = True

        return has_host_check and has_whitelist_hint


    def _adjust_confidence(
        self, sn: CSharpSemanticNode, pattern: SinkPattern
    ) -> TaintConfidence:
        """
        Ajusta la confianza del pattern basándose en el contexto del nodo.
        """
        base = pattern.confidence

        # Si está en try/catch: la excepción puede manejar el error → bajar confianza
        if sn.is_in_try_block and base == TaintConfidence.CONFIRMED:
            return TaintConfidence.HIGH

        # Si tiene argumentos directamente tainted (no solo potencialmente)
        if sn.has_potentially_tainted_args and base == TaintConfidence.HIGH:
            return TaintConfidence.CONFIRMED

        return base

    # ─────────────────────────────────────────────────────────────────────────
    #  MATCH DE ATRIBUTOS PELIGROSOS
    # ─────────────────────────────────────────────────────────────────────────

    def _match_attribute_patterns(
        self, model: ParsedCSharpModel, counter: int
    ) -> list[PatternFinding]:
        """Detecta el uso de atributos peligrosos en clases y métodos."""
        findings: list[PatternFinding] = []

        attr_by_name: dict[str, AttributePattern] = {
            p.attribute_name: p for p in ATTRIBUTE_PATTERNS
        }

        for annotation in model.attribute_annotations:
            pattern = attr_by_name.get(annotation.attribute_name)
            if not pattern:
                continue

            counter += 1

            # Resolver el target (método o clase)
            method = model.methods_by_id.get(annotation.target_id)
            cls    = None
            if method:
                cls = model.classes_by_id.get(method.containing_class_id)

            file_ref = method.file if method else ""
            line_ref = method.line_start if method else 0

            findings.append(PatternFinding(
                finding_id=f"pattern-{counter:04d}",
                vulnerability_kind=pattern.vulnerability_kind,
                confidence=pattern.confidence,
                pattern_id=pattern.pattern_id,
                pattern_name=pattern.name,
                file=file_ref,
                line=line_ref,
                column=0,
                code_snippet=f"[{annotation.attribute_name}]",
                resolved_symbol=annotation.resolved_attribute,
                matched_pattern=annotation.attribute_name,
                method_id=annotation.target_id if annotation.target_kind == "method" else None,
                method_name=method.name if method else None,
                class_name=cls.name if cls else None,
                description=pattern.description,
                remediation=pattern.remediation,
                has_tainted_args=False,
                raw_evidence={
                    "attribute": annotation.attribute_name,
                    "target_kind": annotation.target_kind,
                    "cwe": pattern.cwe,
                },
            ))

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  CARGA DE PATRONES DINÁMICOS DESDE REGLAS
    # ─────────────────────────────────────────────────────────────────────────

    def _load_extra_patterns(self, rules: list[dict]) -> dict[str, SinkPattern]:
        """
        Carga patrones adicionales desde las reglas definidas en core/rules/.
        Permite añadir sinks sin modificar este archivo.
        """
        extra: dict[str, SinkPattern] = {}

        for rule in rules:
            if rule.get("rule_type") != "sink":
                continue

            symbol = rule.get("symbol", "")
            if not symbol:
                continue

            try:
                vuln_kind = VulnerabilityKind(rule.get("vulnerability", "UNKNOWN"))
            except ValueError:
                vuln_kind = VulnerabilityKind.UNKNOWN

            try:
                confidence = TaintConfidence(rule.get("confidence", "medium"))
            except ValueError:
                confidence = TaintConfidence.MEDIUM

            extra[symbol] = SinkPattern(
                pattern_id=rule.get("id", f"custom-{symbol[:20]}"),
                name=rule.get("name", symbol),
                symbol_prefix=symbol,
                vulnerability_kind=vuln_kind,
                tainted_arg_positions=tuple(rule.get("tainted_args", [0])),
                always_vulnerable=rule.get("always_vulnerable", False),
                confidence=confidence,
                description=rule.get("description", ""),
                remediation=rule.get("remediation", ""),
                cwe=rule.get("cwe", "CWE-Unknown"),
                cvss_base=float(rule.get("cvss_base", 7.0)),
            )

        logger.debug("PatternMatcher: %d patrones extra cargados desde reglas.", len(extra))
        return extra
