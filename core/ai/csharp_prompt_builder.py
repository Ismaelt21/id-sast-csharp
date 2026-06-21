# =============================================================================
#  csharp-sast / core / ai / csharp_prompt_builder.py
# =============================================================================
#
#  CONSTRUCTOR DE PROMPTS ESPECIALIZADOS EN C#/.NET PARA GEMINI
#  ─────────────────────────────────────────────────────────────
#  Construye los prompts que el GeminiClient envía a Gemini.
#  Este módulo SOLO construye texto — no llama a Gemini directamente.
#
#  RESPONSABILIDADES:
#    1. System prompt de contexto C#/.NET (expertise del modelo)
#    2. Prompts de análisis de vulnerabilidades detectadas
#    3. Prompts de verificación de falsos positivos
#    4. Prompts de análisis batch (múltiples findings)
#    5. Prompts de generación de reglas SAST nuevas
#    6. Prompts de análisis de patrones de código C# inseguros
#
#  DISEÑO:
#    • Cada método retorna un string (el prompt completo)
#    • El system prompt captura expertise de .NET security
#    • Los prompts incluyen ejemplos concretos de C# (few-shot)
#    • El formato de salida siempre es JSON con estructura definida
#    • Instrucciones explícitas para evitar hallucinations
#
#  RELACIÓN CON SemanticAnalyzer:
#    SemanticAnalyzer llama a CSharpPromptBuilder para obtener el prompt
#    y luego pasa el prompt a GeminiClient.analyze_vulnerability().
#
#  RELACIÓN CON RuleGenerator:
#    RuleGenerator llama a CSharpPromptBuilder para el prompt de generación
#    y luego pasa el prompt a GeminiClient.generate_rule().
#
# =============================================================================

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from core.parsers.ast_importer import ParsedCSharpModel
from core.parsers.framework_detector import Framework, FrameworkProfile

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_VULNERABILITY_ANALYSIS = """Eres un experto en seguridad de aplicaciones .NET y C# con más de 12 años de experiencia en:
- SAST (Static Application Security Testing) para aplicaciones C# empresariales
- Penetration testing de aplicaciones ASP.NET Core, ASP.NET MVC y WCF
- Revisión de código seguro para Entity Framework, Dapper, SignalR y gRPC
- Análisis de vulnerabilidades OWASP Top 10 en el contexto específico de .NET

Tu tarea es analizar vulnerabilidades detectadas por un motor SAST en código C# y determinar:
1. Si la vulnerabilidad es real o un falso positivo
2. Si el nivel de confianza debe ajustarse
3. Si hay contexto que el análisis estático no pudo ver

CONOCIMIENTO CLAVE SOBRE C# Y .NET QUE DEBES APLICAR:
- El model binding automático de ASP.NET Core NO significa que los parámetros están sanitizados
- [ApiController] valida ModelState automáticamente pero NO sanitiza contra injection
- Razor (@variable) encodea automáticamente para HTML — solo Html.Raw() es riesgo de XSS
- EF Core con LINQ es inmune a SQL injection — solo FromSqlRaw/ExecuteSqlRaw con string dinámico es riesgo
- async/await NO desaparece el taint — el dato contaminado persiste en la Task<T>
- int.TryParse, Guid.TryParse son sanitizadores fuertes — un int/GUID no puede contener SQL injection
- BinaryFormatter es SIEMPRE inseguro sin importar el contexto — no hay forma segura de usarlo
- Una validación de ModelState.IsValid sin [ApiController] es opcional y puede bypassearse

REGLAS DE ANÁLISIS:
- Sé CONSERVADOR: en caso de duda, mantener la vulnerabilidad como real
- NO marques como FP sin evidencia CLARA en el código mostrado
- Si el sanitizador no está en TODOS los caminos de ejecución → vulnerabilidad real
- Un try/catch NO elimina el riesgo de SQL injection — solo maneja la excepción
- String.Replace para sanitización es débil — probablemente FP NO aplicable
- Un whitelist de valores (Enum, constantes) ES un sanitizador efectivo

FORMATO DE RESPUESTA:
Responde ÚNICAMENTE con JSON válido sin markdown, sin texto adicional, sin bloques ```json y sin comentarios."""


SYSTEM_PROMPT_RULE_GENERATION = """Eres un experto en SAST (Static Application Security Testing) especializado en C# y .NET con experiencia diseñando reglas de detección de vulnerabilidades.

Tu tarea es generar reglas SAST nuevas para el engine csharp-sast basadas en patrones de código inseguro de C#.

ESTRUCTURA DE REGLAS DEL ENGINE:
Las reglas del engine tienen esta estructura:
{
  "id":              "TIPO-CAT-NNN",
  "rule_type":       "sink" | "source" | "sanitizer",
  "symbol":          "Fully.Qualified.Symbol..ctor o método",
  "name":            "Nombre descriptivo de la regla",
  "vulnerability":   "SQL_INJECTION | COMMAND_INJECTION | PATH_TRAVERSAL | XXE | INSECURE_DESERIALIZATION | SSRF | REFLECTION_ABUSE | RAZOR_XSS | XSS | LOG_INJECTION | OPEN_REDIRECT",
  "tainted_args":    [0, 1],
  "always_vulnerable": false,
  "confidence":      "confirmed" | "high" | "medium" | "low",
  "severity":        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "cwe":             "CWE-89",
  "cvss_base":       9.8,
  "description":     "Descripción técnica del riesgo",
  "remediation":     "Cómo corregirlo con código C# de ejemplo",
  "safe_alternative": "Símbolo o patrón seguro equivalente",
  "frameworks":      ["generic", "aspnetcore", "aspnet_mvc", "ef_core", "dapper"],
  "tags":            ["sql", "injection", "ado.net"]
}

REGLAS PARA GENERAR BUENAS REGLAS SAST:
- El symbol debe ser el fully qualified name de Roslyn (namespace.class.method o ..ctor)
- tainted_args indica QUÉ argumentos del método son el sink (posición 0-indexed)
- always_vulnerable=true solo si el método es SIEMPRE inseguro (BinaryFormatter, CSharpScript)
- confidence "confirmed" solo para vulnerabilidades con cero false positives posibles
- La descripción debe explicar POR QUÉ es inseguro, no solo QUÉ hace
- La remediation debe incluir código C# real y funcional
- Los frameworks deben ser restrictivos (no "generic" si solo aplica a aspnetcore)

RESPONDE ÚNICAMENTE con un array JSON de reglas, sin markdown ni texto adicional."""


SYSTEM_PROMPT_PATTERN_ANALYSIS = """Eres un experto en análisis estático de código C# especializado en detectar patrones de código inseguro.

Tu tarea es analizar fragmentos de código C# e identificar:
1. Patrones de vulnerabilidad presentes o potenciales
2. Antipatrones de seguridad específicos de .NET
3. Configuraciones inseguras de frameworks (ASP.NET Core, EF Core, WCF)

RESPONDE ÚNICAMENTE con JSON válido, sin markdown, sin bloques ```json y sin texto adicional."""


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE CONTEXTO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnerabilityContext:
    """Contexto de una vulnerabilidad para construir el prompt de análisis."""
    # Clasificación
    vulnerability_kind: str         # "SQL_INJECTION", etc.
    cwe:                str         # "CWE-89"
    severity:           str         # "CRITICAL", "HIGH", etc.
    confidence:         str         # "confirmed", "high", "medium", "low"
    finding_source:     str         # "taint_analysis", "pattern_match", etc.

    # Framework
    framework:          str         # "aspnetcore", "wcf", etc.
    language_version:   str = "C# .NET 8"

    # Ubicación
    file:               str = ""
    method_name:        str = ""
    class_name:         str = ""
    source_line:        int = 0
    sink_line:          int = 0

    # Etiquetas del taint
    source_label:       str = ""    # "HttpRequest.Query['id']"
    sink_label:         str = ""    # "SqlCommand(query)"
    taint_label:        str = ""    # "USER_INPUT"

    # Camino de taint (para contexto)
    taint_path_summary: list[str] = None  # type: ignore[assignment]

    # Contexto booleano
    is_in_loop:             bool = False
    has_partial_sanitizer:  bool = False
    is_entry_point:         bool = False
    is_async_flow:          bool = False
    partial_sanitizer_name: str  = ""

    # Código del método (nodos semánticos)
    method_code_context:    str = ""   # Código reconstruido del método

    def __post_init__(self) -> None:
        if self.taint_path_summary is None:
            self.taint_path_summary = []


# ─────────────────────────────────────────────────────────────────────────────
#  PROMPT BUILDER PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class CSharpPromptBuilder:
    """
    Constructor de prompts para análisis de C# con Gemini.

    Uso:
        builder = CSharpPromptBuilder()

        # Para SemanticAnalyzer
        prompt        = builder.build_vulnerability_prompt(ctx)
        system_prompt = builder.get_system_prompt_analysis()

        # Para análisis batch
        prompt        = builder.build_batch_summary_prompt(contexts, profile)
        system_prompt = builder.get_system_prompt_analysis()

        # Para RuleGenerator
        prompt        = builder.build_rule_generation_prompt(pattern, examples)
        system_prompt = builder.get_system_prompt_rule_generation()
    """

    # ─────────────────────────────────────────────────────────────────────────
    #  SYSTEM PROMPTS
    # ─────────────────────────────────────────────────────────────────────────

    def get_system_prompt_analysis(self) -> str:
        """System prompt para análisis de vulnerabilidades."""
        return SYSTEM_PROMPT_VULNERABILITY_ANALYSIS

    def get_system_prompt_rule_generation(self) -> str:
        """System prompt para generación de reglas SAST."""
        return SYSTEM_PROMPT_RULE_GENERATION

    def get_system_prompt_pattern_analysis(self) -> str:
        """System prompt para análisis de patrones de código."""
        return SYSTEM_PROMPT_PATTERN_ANALYSIS

    # ─────────────────────────────────────────────────────────────────────────
    #  PROMPT DE ANÁLISIS DE VULNERABILIDAD INDIVIDUAL
    # ─────────────────────────────────────────────────────────────────────────

    def build_vulnerability_prompt(
        self,
        ctx: VulnerabilityContext,
    ) -> str:
        """
        Construye el prompt de análisis para una vulnerabilidad específica.

        Estructura del prompt:
          1. Header con clasificación de la vulnerabilidad
          2. Contexto del framework y versión
          3. Flujo de taint (source → sink con path)
          4. Código del método (contexto semántico)
          5. Contexto booleano adicional
          6. Esquema de respuesta JSON esperado

        Args:
            ctx: VulnerabilityContext con todos los datos de la vulnerabilidad.

        Returns:
            String con el prompt completo listo para enviar a Gemini.
        """
        # ── Sección 1: Header de clasificación ───────────────────────────────
        header = self._build_classification_header(ctx)

        # ── Sección 2: Contexto de framework ─────────────────────────────────
        framework_ctx = self._build_framework_context(ctx)

        # ── Sección 3: Flujo de taint ─────────────────────────────────────────
        taint_section = self._build_taint_flow_section(ctx)

        # ── Sección 4: Código del método ──────────────────────────────────────
        code_section = self._build_code_section(ctx)

        # ── Sección 5: Contexto booleano ──────────────────────────────────────
        context_section = self._build_boolean_context(ctx)

        # ── Sección 6: Esquema de respuesta ───────────────────────────────────
        response_schema = self._build_analysis_response_schema()

        return "\n\n".join([
            header,
            framework_ctx,
            taint_section,
            code_section,
            context_section,
            response_schema,
        ])

    def _build_classification_header(self, ctx: VulnerabilityContext) -> str:
        """Header con la clasificación de la vulnerabilidad."""
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
        }.get(ctx.severity, "⚪")

        confidence_desc = {
            "confirmed": "Confirmada (análisis estático determinista)",
            "high":      "Alta (flujo de taint directo, pocos saltos)",
            "medium":    "Media (flujo condicional o inter-procedural)",
            "low":       "Baja (múltiples caminos posibles, heurística)",
        }.get(ctx.confidence, ctx.confidence)

        return f"""## VULNERABILIDAD DETECTADA — ANÁLISIS REQUERIDO

**Tipo**: {ctx.vulnerability_kind} ({ctx.cwe})
**Severidad calculada**: {severity_emoji} {ctx.severity}
**Confianza del análisis estático**: {confidence_desc}
**Fuente del análisis**: {ctx.finding_source}

**Archivo**: `{ctx.file.split('/')[-1] if ctx.file else 'N/A'}`
**Clase**: `{ctx.class_name or 'N/A'}`
**Método**: `{ctx.method_name or 'N/A'}()`
**Línea source**: L{ctx.source_line}
**Línea sink**: L{ctx.sink_line}"""

    def _build_framework_context(self, ctx: VulnerabilityContext) -> str:
        """Contexto del framework para guiar el análisis."""
        framework_notes = {
            "aspnetcore": (
                "ASP.NET Core con model binding automático. "
                "Los parámetros de action methods son automáticamente tainted. "
                "Verificar si hay [ApiController] (valida ModelState) "
                "o [Authorize] (requiere autenticación)."
            ),
            "aspnet_mvc": (
                "ASP.NET MVC clásico (System.Web). "
                "Model binding manual. "
                "ValidateInput(false) desactiva protección HTML."
            ),
            "wcf": (
                "Windows Communication Foundation. "
                "Los parámetros de [OperationContract] son tainted. "
                "Verificar BasicHttpBinding sin seguridad de transporte."
            ),
            "ef_core": (
                "Entity Framework Core. "
                "LINQ es inmune a SQL injection. "
                "Solo FromSqlRaw/ExecuteSqlRaw con string dinámico es riesgo."
            ),
            "generic": (
                "Aplicación .NET genérica (consola, servicio Windows, etc.)."
            ),
        }

        framework_note = framework_notes.get(
            ctx.framework,
            f"Framework: {ctx.framework}"
        )

        return f"""## CONTEXTO DEL FRAMEWORK

**Framework**: {ctx.framework} ({ctx.language_version})
**Nota de framework**: {framework_note}
**Es endpoint público**: {"Sí" if ctx.is_entry_point else "No"}
**Flujo asíncrono (async/await)**: {"Sí" if ctx.is_async_flow else "No"}"""

    def _build_taint_flow_section(self, ctx: VulnerabilityContext) -> str:
        """Sección de flujo de taint source → sink."""
        source_info = f"`{ctx.source_label}`" if ctx.source_label else "N/A"
        sink_info   = f"`{ctx.sink_label}`" if ctx.sink_label else "N/A"
        taint_info  = f"`{ctx.taint_label}`" if ctx.taint_label else "USER_INPUT"

        # Camino de taint
        if ctx.taint_path_summary:
            path_lines = "\n".join(
                f"  {i+1}. {step}" for i, step in enumerate(ctx.taint_path_summary)
            )
            path_section = f"\n**Camino de taint**:\n{path_lines}"
        else:
            path_section = "\n*(Análisis por patrón — sin camino de taint detallado)*"

        # Sanitizador parcial
        san_section = ""
        if ctx.has_partial_sanitizer:
            san_name = ctx.partial_sanitizer_name or "desconocido"
            san_section = (
                f"\n\n⚠️ **Sanitizador parcial detectado**: `{san_name}` "
                f"fue encontrado en el camino pero NO cubre todos los flujos "
                f"de ejecución posibles."
            )

        # In loop
        loop_section = ""
        if ctx.is_in_loop:
            loop_section = (
                "\n\n⚠️ **Sink en loop**: El sink está dentro de un loop — "
                "la vulnerabilidad puede explotarse repetidamente, "
                "amplificando el impacto."
            )

        return f"""## FLUJO DE TAINT

**Origen del dato contaminado** (source): {source_info}
**Label de taint**: {taint_info}
**Destino vulnerable** (sink): {sink_info}
{path_section}{san_section}{loop_section}"""

    def _build_code_section(self, ctx: VulnerabilityContext) -> str:
        """Sección de código del método para contexto."""
        if not ctx.method_code_context:
            return "## CÓDIGO DEL MÉTODO\n*(No disponible — análisis por patrón)*"

        # Truncar si es muy largo
        code = ctx.method_code_context
        if len(code) > 2000:
            code = code[:2000] + "\n  // ... [truncado para reducir tokens]"

        return f"""## CÓDIGO DEL MÉTODO (CONTEXTO SEMÁNTICO)

```csharp
{code}
```

*Leyenda: [SOURCE] = origen del dato tainted | [SINK ⚠️] = destino vulnerable | [SANITIZER ✓] = sanitizador*"""

    def _build_boolean_context(self, ctx: VulnerabilityContext) -> str:
        """Contexto adicional en formato de checkboxes."""

        def checkbox(val: bool) -> str:
            return "✅" if val else "❌"

        return f"""## CONTEXTO ADICIONAL

| Factor | Estado |
|--------|--------|
| Endpoint público (sin autenticación) | {checkbox(ctx.is_entry_point)} |
| Sanitizador parcial en el camino | {checkbox(ctx.has_partial_sanitizer)} |
| Sink dentro de un loop | {checkbox(ctx.is_in_loop)} |
| Flujo async/await | {checkbox(ctx.is_async_flow)} |"""

    def _build_json_output_contract(self, expected_shape: str) -> str:
        """Contrato estricto para que Gemini responda sin markdown ni fences."""
        return f"""## CONTRATO DE SALIDA

Debes responder solo con {expected_shape}.
- No uses bloques ```json ni cualquier otro bloque markdown.
- No agregues texto antes ni después del JSON.
- No incluyas comentarios, explicaciones ni notas.
- Todos los valores de tipo string deben ir en una sola línea.
- Si un campo no aplica, usa null, [] o "" según corresponda.
- Mantén exactamente el esquema pedido y respeta el tipo de cada campo."""

    def _build_analysis_response_schema(self) -> str:
        """Esquema JSON esperado en la respuesta de análisis."""
        return """## RESPUESTA REQUERIDA

Responde ÚNICAMENTE con este JSON válido (sin markdown, sin texto adicional, sin comentarios):

{
  "is_false_positive": false,
  "reasoning": "Explicación concisa de por qué es real o FP (máx 250 caracteres). Menciona evidencia específica del código mostrado.",
  "confidence_adjusted": null,
  "severity_adjusted": null,
  "enriched_description": "Descripción enriquecida con contexto específico de C#/.NET (máx 350 caracteres)",
  "enriched_remediation": "Remediación específica para este caso concreto con código C# de ejemplo (máx 400 caracteres)",
  "suggested_fix": "Snippet de código C# corregido (máx 6 líneas, null si no aplica)"
}

Valores permitidos:
- is_false_positive: true | false
- confidence_adjusted: "confirmed" | "high" | "medium" | "low" | null (null = sin cambio)
- severity_adjusted: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | null (null = sin cambio)
- suggested_fix: string con código C# | null"""

    # ─────────────────────────────────────────────────────────────────────────
    #  PROMPT DE ANÁLISIS BATCH
    # ─────────────────────────────────────────────────────────────────────────

    def build_batch_summary_prompt(
        self,
        contexts: list[VulnerabilityContext],
        profile:  FrameworkProfile,
    ) -> str:
        """
        Prompt de análisis batch para múltiples findings de menor prioridad.

        Usado por SemanticAnalyzer para findings de confianza MEDIUM
        donde el análisis individual no justifica el coste de tokens.

        Args:
            contexts: Lista de VulnerabilityContext a analizar en batch.
            profile:  FrameworkProfile del proyecto analizado.

        Returns:
            Prompt batch compacto con todos los findings.
        """
        framework_name = profile.primary_framework.value
        total = len(contexts)

        # Construir tabla compacta de findings
        findings_rows = []
        for i, ctx in enumerate(contexts, 1):
            file_short = ctx.file.split("/")[-1] if ctx.file else "?"
            method     = ctx.method_name or "?"
            source_s   = ctx.source_label[:40] if ctx.source_label else "?"
            sink_s     = ctx.sink_label[:40] if ctx.sink_label else "?"
            code_s     = ctx.method_code_context[:100].replace('\n', ' ') if ctx.method_code_context else ""

            findings_rows.append(
                f"{i}. [{ctx.vulnerability_kind}] {ctx.class_name}.{method}() "
                f"L{ctx.sink_line} ({file_short})\n"
                f"   Source: {source_s}\n"
                f"   Sink: {sink_s}\n"
                f"   Código: {code_s}\n"
                f"   In loop: {ctx.is_in_loop} | "
                f"Partial sanitizer: {ctx.has_partial_sanitizer} | "
                f"Entry point: {ctx.is_entry_point}"
            )

        findings_text = "\n\n".join(findings_rows)

        return f"""Eres un experto en seguridad .NET. Analiza estos {total} findings de SAST "
f"en código C# ({framework_name}).

## FINDINGS A ANALIZAR

{findings_text}

## CONOCIMIENTO APLICABLE
- ASP.NET Core: parámetros de action methods son tainted por model binding
- LINQ es seguro; FromSqlRaw con string dinámico NO lo es
- int/Guid.TryParse son sanitizadores fuertes (no pueden contener injection)
- async/await no elimina el taint
- Un try/catch no previene SQL injection
- Si la evidencia es débil o ambigua, marca `is_likely_fp` como true.
- Mantén `reason` en una sola oración corta, sin saltos de línea ni listas.
- Responde solo con datos estrictamente respaldados por el fragmento mostrado.

## RESPUESTA REQUERIDA

Responde ÚNICAMENTE con este JSON válido (sin markdown, sin fences y sin texto adicional):

{{
  "findings": [
    {{
      "index": 1,
      "is_likely_fp": false,
      "confidence_note": "confirmed|high|medium|low",
      "reason": "razón concisa en máx 120 chars"
    }}
  ]
}}

Incluye un objeto por cada finding en el mismo orden.

## CONTRATO DE SALIDA

Debes devolver exactamente un objeto JSON con la clave `findings`.
- No uses ```json ni texto fuera del JSON.
- No cambies el orden de los findings.
- Todos los valores de tipo string deben ir en una sola línea.
- Si un finding no puede ser confirmado, marca `is_likely_fp` como true y explica la razón con concisión."""

    # ─────────────────────────────────────────────────────────────────────────
    #  PROMPT DE GENERACIÓN DE REGLAS
    # ─────────────────────────────────────────────────────────────────────────

    def build_rule_generation_prompt(
        self,
        pattern_description: str,
        code_examples:       list[str],
        vulnerability_kind:  str | None = None,
        frameworks:          list[str] | None = None,
        existing_rules:      list[str] | None = None,
    ) -> str:
        """
        Construye el prompt para generar nuevas reglas SAST desde un patrón.

        Args:
            pattern_description: Descripción del patrón de código inseguro.
            code_examples:       Ejemplos de código C# vulnerable.
            vulnerability_kind:  Tipo de vulnerabilidad (si se conoce).
            frameworks:          Frameworks donde aplica.
            existing_rules:      IDs de reglas existentes (para evitar duplicados).

        Returns:
            Prompt para GeminiClient.generate_rule().
        """
        # Formatear ejemplos de código
        examples_section = ""
        if code_examples:
            formatted = "\n\n".join(
                f"**Ejemplo {i+1}**:\n```csharp\n{ex}\n```"
                for i, ex in enumerate(code_examples[:3])  # Max 3 ejemplos
            )
            examples_section = f"\n\n## EJEMPLOS DE CÓDIGO VULNERABLE\n\n{formatted}"

        # Contexto de vuln kind
        vuln_hint = (
            f"\n\n**Tipo de vulnerabilidad esperado**: {vulnerability_kind}"
            if vulnerability_kind else ""
        )

        # Frameworks
        fw_hint = ""
        if frameworks:
            fw_hint = f"\n\n**Frameworks relevantes**: {', '.join(frameworks)}"

        # Reglas existentes (para evitar duplicados)
        existing_hint = ""
        if existing_rules:
            existing_hint = (
                f"\n\n**Reglas ya existentes** (NO duplicar): "
                f"{', '.join(existing_rules[:10])}"
            )

        # Ejemplos few-shot de reglas bien formadas
        fewshot = self._build_rule_fewshot_examples()

        return f"""## TAREA DE GENERACIÓN DE REGLAS SAST

Necesito reglas SAST nuevas para detectar el siguiente patrón de código inseguro en C#:

## PATRÓN A DETECTAR

{pattern_description}{vuln_hint}{fw_hint}{examples_section}{existing_hint}

## EJEMPLOS DE REGLAS BIEN FORMADAS

{fewshot}

## INSTRUCCIONES

1. Genera entre 1 y 5 reglas SAST que detecten el patrón descrito
2. Cubre todas las variantes del patrón (sobrecargas de métodos, versiones async, etc.)
3. El symbol debe ser el fully qualified name de Roslyn del método/constructor
4. La description debe explicar POR QUÉ es inseguro (no solo qué hace)
5. La remediation debe incluir código C# funcional y concreto
6. No dupliques reglas existentes listadas arriba
7. Los cvss_base deben seguir el estándar CVSS v3.1

Responde ÚNICAMENTE con un array JSON de reglas, sin markdown, sin fences y sin texto adicional:

[
  {{
    "id": "...",
    "rule_type": "sink",
    ...
  }}
]

## CONTRATO DE SALIDA

Devuelve únicamente un array JSON.
- No agregues comentarios ni explicación fuera del array.
- No uses ```json ni bloques de código.
- Todos los valores de tipo string deben ir en una sola línea.
- Cada elemento debe respetar exactamente la estructura esperada."""

    def _build_rule_fewshot_examples(self) -> str:
        """Ejemplos few-shot de reglas bien formadas para guiar la generación."""
        example_sink = {
            "id": "SQL-ADO-001",
            "rule_type": "sink",
            "symbol": "System.Data.SqlClient.SqlCommand..ctor",
            "name": "SqlCommand constructor con query dinámica",
            "vulnerability": "SQL_INJECTION",
            "tainted_args": [0],
            "always_vulnerable": False,
            "confidence": "high",
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "cvss_base": 9.8,
            "description": (
                "SqlCommand construido con query SQL dinámica en el primer argumento. "
                "Si el string contiene input del usuario sin parametrizar → SQL Injection completo."
            ),
            "remediation": (
                "Usar SqlParameter: cmd.Parameters.AddWithValue('@id', userId). "
                "Con EF Core: usar LINQ o FromSqlInterpolated. Con Dapper: new { Id = id }."
            ),
            "safe_alternative": "System.Data.SqlClient.SqlParameter",
            "frameworks": ["generic", "aspnetcore", "aspnet_mvc"],
            "tags": ["sql", "ado.net", "injection"],
        }

        example_sanitizer = {
            "id": "SAN-VAL-001",
            "rule_type": "sanitizer",
            "symbol": "System.Int32.TryParse",
            "name": "int.TryParse — validación de entero",
            "sanitizes": ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"],
            "sanitizer_type": "VALIDATION",
            "confidence": 0.97,
            "limitations": "Sanitiza el int resultante, NO el string original.",
            "description": (
                "int.TryParse convierte string a int. "
                "Un int válido no puede contener SQL injection ni metacaracteres de shell."
            ),
            "frameworks": ["generic", "aspnetcore"],
            "tags": ["validation", "type-check", "integer"],
        }

        return (
            "**Ejemplo de sink**:\n```json\n"
            + json.dumps(example_sink, indent=2, ensure_ascii=False)
            + "\n```\n\n**Ejemplo de sanitizador**:\n```json\n"
            + json.dumps(example_sanitizer, indent=2, ensure_ascii=False)
            + "\n```"
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  PROMPT DE ANÁLISIS DE PATRÓN DE CÓDIGO
    # ─────────────────────────────────────────────────────────────────────────

    def build_pattern_analysis_prompt(
        self,
        code_snippet:  str,
        file_context:  str = "",
        framework:     str = "generic",
    ) -> str:
        """
        Prompt para analizar un fragmento de código C# en busca de patrones inseguros.

        Usado por RuleGenerator para extraer patrones de código vulnerable
        antes de generar reglas.

        Args:
            code_snippet:  Fragmento de código C# a analizar.
            file_context:  Ruta del archivo (para contexto).
            framework:     Framework del proyecto.

        Returns:
            Prompt de análisis de patrón.
        """
        file_info = f" (archivo: {file_context.split('/')[-1]})" if file_context else ""

        # Truncar snippet si es muy largo
        snippet = code_snippet
        if len(snippet) > 3000:
            snippet = snippet[:3000] + "\n// ... [truncado]"

        return f"""## ANÁLISIS DE PATRONES DE SEGURIDAD EN C#

Analiza el siguiente código C#{file_info} en busca de patrones de vulnerabilidad.
**Framework**: {framework}

## CÓDIGO A ANALIZAR

```csharp
{snippet}
```

## INSTRUCCIONES

Identifica:
1. Todos los patrones de código inseguro presentes (aunque sean sutiles)
2. El tipo de vulnerabilidad de cada patrón (SQL Injection, XSS, Path Traversal, etc.)
3. El símbolo exacto de .NET involucrado (fully qualified name)
4. Si el patrón ya tiene sanitización o parametrización
5. Qué posición de argumento recibe el dato inseguro

## RESPUESTA REQUERIDA

```json
{{
  "patterns_found": [
    {{
      "vulnerability_type": "SQL_INJECTION",
      "symbol": "System.Data.SqlClient.SqlCommand..ctor",
      "description": "SqlCommand construido con concatenación de string",
      "line_hint": 15,
      "argument_position": 0,
      "has_sanitization": false,
      "sanitization_details": null,
      "severity_estimate": "CRITICAL"
    }}
  ],
  "safe_patterns_found": [
    {{
      "description": "LINQ query — inmune a SQL injection por diseño"
    }}
  ],
  "summary": "Resumen ejecutivo del análisis (máx 200 chars)"
}}
```"""

    # ─────────────────────────────────────────────────────────────────────────
    #  PROMPT DE VERIFICACIÓN DE FALSO POSITIVO (rápido)
    # ─────────────────────────────────────────────────────────────────────────

    def build_false_positive_check_prompt(
        self,
        ctx:          VulnerabilityContext,
        reason_hint:  str = "",
    ) -> str:
        """
        Prompt compacto y rápido para verificar si un finding es falso positivo.

        Más corto que build_vulnerability_prompt — para verificaciones rápidas
        donde solo se necesita la decisión FP/Real sin enriquecimiento.

        Args:
            ctx:         Contexto de la vulnerabilidad.
            reason_hint: Razón por la que se sospecha que puede ser FP.

        Returns:
            Prompt compacto de verificación de FP.
        """
        hint_section = (
            f"\n\n**Razón de sospecha de FP**: {reason_hint}"
            if reason_hint else ""
        )

        code_section = ""
        if ctx.method_code_context:
            code = ctx.method_code_context[:800]
            code_section = f"\n\n**Código relevante**:\n```csharp\n{code}\n```"

        return f"""¿Es este finding un falso positivo?

**Tipo**: {ctx.vulnerability_kind} | **Confianza**: {ctx.confidence}
**Método**: {ctx.class_name}.{ctx.method_name}()
**Source**: {ctx.source_label or 'N/A'}
**Sink**: {ctx.sink_label or 'N/A'}
**Framework**: {ctx.framework}{hint_section}{code_section}

Responde ÚNICAMENTE con JSON:

{{
  "is_false_positive": false,
  "confidence": "high",
  "reason": "Razón concisa (máx 150 chars)"
}}"""

    # ─────────────────────────────────────────────────────────────────────────
    #  BUILDER HELPER: construir contexto desde ClassifiedVulnerability
    # ─────────────────────────────────────────────────────────────────────────

    def build_context_from_classified(
        self,
        vuln:   Any,   # ClassifiedVulnerability (evitar import circular)
        model:  ParsedCSharpModel | None = None,
        profile: FrameworkProfile | None = None,
    ) -> VulnerabilityContext:
        """
        Construye un VulnerabilityContext desde una ClassifiedVulnerability.

        Convenience method para el SemanticAnalyzer — evita que el analyzer
        deba construir el contexto manualmente.

        Args:
            vuln:    ClassifiedVulnerability del VulnerabilityClassifier.
            model:   ParsedCSharpModel para obtener código del método.
            profile: FrameworkProfile del proyecto.

        Returns:
            VulnerabilityContext listo para build_vulnerability_prompt().
        """
        framework = "generic"
        if profile:
            framework = profile.primary_framework.value

        # Extraer código del método si el modelo está disponible
        method_code = ""
        if model and vuln.method_name:
            method_code = self._extract_method_code_context(
                vuln.method_name, vuln.class_name, model
            )

        # Taint path como lista de strings
        path_summary: list[str] = []
        if hasattr(vuln, "taint_path_summary"):
            path_summary = vuln.taint_path_summary or []
        elif hasattr(vuln, "original_findings"):
            for finding in vuln.original_findings[:1]:
                if hasattr(finding, "taint_path"):
                    path_summary = [
                        f"L{step.line}: {step.label[:60]}"
                        for step in finding.taint_path[:8]
                    ]

        return VulnerabilityContext(
            vulnerability_kind=vuln.vulnerability_kind.value
                if hasattr(vuln.vulnerability_kind, "value")
                else str(vuln.vulnerability_kind),
            cwe=vuln.cwe,
            severity=vuln.severity.value
                if hasattr(vuln.severity, "value")
                else str(vuln.severity),
            confidence=vuln.confidence.value
                if hasattr(vuln.confidence, "value")
                else str(vuln.confidence),
            finding_source=vuln.finding_source.value
                if hasattr(vuln.finding_source, "value")
                else str(vuln.finding_source),
            framework=framework,
            file=vuln.file or "",
            method_name=vuln.method_name or "",
            class_name=vuln.class_name or "",
            source_line=getattr(vuln, "line", 0),
            sink_line=getattr(vuln, "sink_line", 0),
            source_label=getattr(vuln, "source_label", ""),
            sink_label=getattr(vuln, "sink_label", vuln.code_snippet[:60]),
            taint_label=getattr(vuln, "taint_label", "USER_INPUT"),
            taint_path_summary=path_summary,
            is_in_loop=getattr(vuln, "is_in_loop", False),
            has_partial_sanitizer=getattr(vuln, "has_partial_sanitizer", False),
            is_entry_point=getattr(vuln, "is_entry_point", False),
            is_async_flow=bool(getattr(vuln, "raw_evidence", {}).get("has_async")),
            method_code_context=method_code,
        )

    def _extract_method_code_context(
        self,
        method_name: str,
        class_name:  str | None,
        model:       ParsedCSharpModel,
    ) -> str:
        """Extrae el código del método como string de contexto."""
        # Buscar el método en el modelo
        for cls in model.classes:
            if class_name and cls.name != class_name:
                continue
            for method in cls.methods:
                if method.name != method_name:
                    continue

                # Reconstruir contexto desde nodos semánticos
                nodes = model.nodes_by_method.get(method.method_id, [])
                nodes_sorted = sorted(nodes, key=lambda n: n.line)

                lines: list[str] = [f"// {method.signature}"]
                for node in nodes_sorted[:25]:
                    prefix = ""
                    if node.is_known_source:
                        prefix = "// [SOURCE] "
                    elif node.is_known_sink:
                        prefix = "// [SINK ⚠️] "
                    elif node.is_known_sanitizer:
                        prefix = "// [SANITIZER ✓] "
                    lines.append(f"  L{node.line}: {prefix}{node.text[:100]}")

                return "\n".join(lines)

        return ""
