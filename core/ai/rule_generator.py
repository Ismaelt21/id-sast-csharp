# =============================================================================
#  csharp-sast / core / ai / rule_generator.py
# =============================================================================
#
#  GENERADOR DE REGLAS SAST PARA C# USANDO GEMINI
#  ─────────────────────────────────────────────────
#  Genera nuevas reglas SAST para el engine csharp-sast analizando
#  patrones de código inseguro de C# con la IA de Google Gemini.
#
#  FLUJO DE GENERACIÓN:
#    1. El usuario describe un patrón de código inseguro (o provee código)
#    2. CSharpPromptBuilder construye el prompt especializado en C#
#    3. GeminiClient.generate_rule() envía a Gemini y obtiene JSON
#    4. RuleGenerator valida el JSON contra el schema del engine
#    5. Si es válido → GeneratedRule con metadata de trazabilidad
#    6. Export → archivo .py compatible con los catálogos del engine
#       o archivo .json para revisión manual
#
#  RESPONSABILIDADES:
#    • Orquestar GeminiClient + CSharpPromptBuilder → GeneratedRule
#    • Validar que las reglas generadas cumplen el schema del engine
#    • Detectar colisiones con reglas existentes (mismo symbol)
#    • Asignar IDs únicos con el prefijo GEN- (reglas generadas por IA)
#    • Exportar reglas en formato .py (para añadir a catálogos)
#      o .json (para revisión antes de integrar)
#    • Analizar snippets de código C# para descubrir sinks desconocidos
#
#  DISEÑO DE IDs:
#    Las reglas generadas por IA usan el prefijo GEN- para distinguirlas
#    de las reglas built-in (SQL-ADO-001, PATH-001, etc.).
#    Formato: GEN-{VULN_PREFIX}-{NNN}
#    Ejemplos: GEN-SQL-001, GEN-PATH-042, GEN-SAN-007
#
#  INTEGRACIÓN CON EL ENGINE:
#    Las reglas generadas se pueden:
#    a) Añadir manualmente a los catálogos después de revisión humana
#    b) Cargar como reglas custom via RuleLoader(custom_path=Path("./gen_rules"))
#    c) Usar directamente desde el JSON generado (sin revisión — no recomendado)
#
#  NO HACER:
#    • No cargar reglas de IA sin revisión humana en producción
#    • No confiar en las reglas generadas sin verificar el symbol en Roslyn
#    • No publicar las reglas como "built-in" sin pruebas de falsos positivos
#
# =============================================================================

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.ai.csharp_prompt_builder import CSharpPromptBuilder
from core.ai.gemini_client import GeminiClient

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTES DEL SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

# Tipos de regla soportados
VALID_RULE_TYPES = {"sink", "source", "sanitizer"}

# Tipos de vulnerabilidad soportados (alineados con los catálogos built-in)
VALID_VULNERABILITY_KINDS = {
    "SQL_INJECTION",
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "XXE",
    "INSECURE_DESERIALIZATION",
    "SSRF",
    "REFLECTION_ABUSE",
    "RAZOR_XSS",
    "XSS",
    "LOG_INJECTION",
    "OPEN_REDIRECT",
    "CSRF",
}

# Niveles de confianza para sinks (strings)
VALID_SINK_CONFIDENCES = {"confirmed", "high", "medium", "low"}

# Severidades
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# Frameworks soportados
VALID_FRAMEWORKS = {
    "generic", "aspnetcore", "aspnet_mvc", "wcf",
    "ef_core", "ef6", "dapper", "console", "grpc",
    "signalr", "winforms",
}

# Taint labels para sources
VALID_TAINT_LABELS = {
    "USER_INPUT", "EXTERNAL_INPUT", "NETWORK_INPUT",
    "STORED_INPUT", "ENVIRONMENT_INPUT",
}

# Tipos de sanitizador
VALID_SANITIZER_TYPES = {"ENCODING", "VALIDATION", "PARAMETERIZATION"}

# Mapeo de vulnerability → prefijo de ID para reglas generadas
_VULN_ID_PREFIX: dict[str, str] = {
    "SQL_INJECTION":         "GEN-SQL",
    "COMMAND_INJECTION":     "GEN-CMD",
    "PATH_TRAVERSAL":        "GEN-PATH",
    "XXE":                   "GEN-XXE",
    "INSECURE_DESERIALIZATION": "GEN-DESER",
    "SSRF":                  "GEN-SSRF",
    "REFLECTION_ABUSE":      "GEN-REFLECT",
    "RAZOR_XSS":             "GEN-XSS",
    "XSS":                   "GEN-XSS",
    "LOG_INJECTION":         "GEN-LOG",
    "OPEN_REDIRECT":         "GEN-REDIRECT",
    "CSRF":                  "GEN-CSRF",
}

# Prefijos para sources y sanitizers generados
_SOURCE_ID_PREFIX    = "GEN-SRC"
_SANITIZER_ID_PREFIX = "GEN-SAN"


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """
    Resultado de la validación de una regla generada por Gemini.
    Describe si la regla es válida para el engine y qué problemas tiene.
    """
    is_valid:         bool
    rule_type:        str | None = None   # "sink" | "source" | "sanitizer"
    errors:           list[str] = field(default_factory=list)
    warnings:         list[str] = field(default_factory=list)
    auto_fixed:       list[str] = field(default_factory=list)  # Correcciones automáticas

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    def __repr__(self) -> str:
        status = "✅ VALID" if self.is_valid else "❌ INVALID"
        return (
            f"ValidationResult({status}, "
            f"errors={len(self.errors)}, "
            f"warnings={len(self.warnings)}, "
            f"fixes={len(self.auto_fixed)})"
        )


@dataclass
class GeneratedRule:
    """
    Regla SAST generada por Gemini, validada y lista para exportar.

    La regla puede usarse directamente como custom rule en RuleLoader
    o exportarse a un archivo .py / .json para revisión humana.
    """
    # La regla en sí (dict compatible con el engine)
    rule:             dict[str, Any]

    # Metadata de generación
    generated_at:     str
    gemini_model:     str
    pattern_source:   str           # "pattern_description" | "code_analysis" | "manual"
    generation_id:    str           # UUID único de esta generación
    confidence_ai:    float         # Confianza del modelo AI (0.0-1.0)

    # Resultado de validación
    validation:       ValidationResult

    # Colisiones detectadas con reglas existentes
    collisions:       list[str] = field(default_factory=list)

    # Hash del raw prompt (para deduplicación)
    prompt_hash:      str | None = None

    @property
    def rule_id(self) -> str:
        return self.rule.get("id", "?")

    @property
    def rule_type(self) -> str:
        return self.rule.get("rule_type", "?")

    @property
    def symbol(self) -> str:
        return self.rule.get("symbol", "?")

    @property
    def is_production_ready(self) -> bool:
        """
        True si la regla pasó validación y no tiene colisiones.
        Todavía se recomienda revisión humana antes de usar en producción.
        """
        return self.validation.is_valid and not self.collisions

    def to_dict(self) -> dict[str, Any]:
        """Serialización completa para JSON export."""
        return {
            "rule":           self.rule,
            "metadata": {
                "generated_at":   self.generated_at,
                "gemini_model":   self.gemini_model,
                "pattern_source": self.pattern_source,
                "generation_id":  self.generation_id,
                "confidence_ai":  self.confidence_ai,
            },
            "validation": {
                "is_valid":   self.validation.is_valid,
                "errors":     self.validation.errors,
                "warnings":   self.validation.warnings,
                "auto_fixed": self.validation.auto_fixed,
            },
            "collisions": self.collisions,
        }

    def __repr__(self) -> str:
        ready = "✅" if self.is_production_ready else "⚠️"
        return (
            f"GeneratedRule({ready} {self.rule_id} | "
            f"{self.rule_type} | conf_ai={self.confidence_ai:.2f})"
        )


@dataclass
class GenerationResult:
    """
    Resultado de una operación de generación completa.
    Puede contener múltiples GeneratedRule de una sola llamada a Gemini.
    """
    rules:            list[GeneratedRule]
    pattern_source:   str
    generation_time_ms: float
    gemini_success:   bool
    gemini_error:     str | None = None

    # Stats
    @property
    def total_generated(self) -> int:
        return len(self.rules)

    @property
    def valid_count(self) -> int:
        return sum(1 for r in self.rules if r.validation.is_valid)

    @property
    def production_ready_count(self) -> int:
        return sum(1 for r in self.rules if r.is_production_ready)

    @property
    def has_any_valid(self) -> bool:
        return self.valid_count > 0

    def get_valid_rules(self) -> list[GeneratedRule]:
        return [r for r in self.rules if r.validation.is_valid]

    def get_production_ready(self) -> list[GeneratedRule]:
        return [r for r in self.rules if r.is_production_ready]

    def summary(self) -> str:
        return (
            f"GenerationResult("
            f"generated={self.total_generated}, "
            f"valid={self.valid_count}, "
            f"production_ready={self.production_ready_count}, "
            f"gemini={'OK' if self.gemini_success else 'FAIL'}, "
            f"time={self.generation_time_ms:.0f}ms)"
        )

    def __repr__(self) -> str:
        return self.summary()


# ─────────────────────────────────────────────────────────────────────────────
#  GENERADOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class RuleGenerator:
    """
    Generador de reglas SAST para C# usando Gemini.

    Orquesta CSharpPromptBuilder y GeminiClient para generar reglas
    válidas para el engine csharp-sast.

    Uso:
        generator = RuleGenerator(gemini_client)

        # Generar desde descripción de patrón
        result = await generator.generate_from_pattern(
            pattern_description="HttpClient.GetAsync con URL controlada por el usuario",
            code_examples=["var resp = await client.GetAsync(userUrl);"],
            vulnerability_kind="SSRF",
            frameworks=["aspnetcore"],
        )

        # Generar desde análisis de código
        result = await generator.generate_from_code_analysis(
            code_snippet=open("MyController.cs").read(),
            framework="aspnetcore",
        )

        # Exportar reglas válidas
        if result.has_any_valid:
            generator.export_to_python(result.get_valid_rules(), Path("./gen_rules"))
    """

    def __init__(
        self,
        gemini_client:  GeminiClient,
        prompt_builder: CSharpPromptBuilder | None = None,
        existing_rules: list[dict[str, Any]] | None = None,
    ) -> None:
        """
        Args:
            gemini_client:  Cliente Gemini inicializado.
            prompt_builder: CSharpPromptBuilder (se crea uno si None).
            existing_rules: Lista de reglas existentes para detectar colisiones.
                            Si None, no hay detección de colisiones.
        """
        self._gemini  = gemini_client
        self._builder = prompt_builder or CSharpPromptBuilder()

        # Construir índices de reglas existentes para colisión y IDs
        self._existing_symbols: set[str] = set()
        self._existing_ids:     set[str] = set()
        self._id_counters:      dict[str, int] = {}

        if existing_rules:
            self._index_existing_rules(existing_rules)

        # Contador global de generaciones para IDs únicos
        self._generation_counter = 0

    # ─────────────────────────────────────────────────────────────────────────
    #  MÉTODOS PRINCIPALES DE GENERACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    async def generate_from_pattern(
        self,
        pattern_description: str,
        code_examples:       list[str] | None = None,
        vulnerability_kind:  str | None = None,
        frameworks:          list[str] | None = None,
        timeout_sec:         float = 45.0,
    ) -> GenerationResult:
        """
        Genera reglas SAST desde una descripción de patrón de código inseguro.

        Es el método principal para añadir soporte para nuevas librerías
        o APIs de C# que el engine no cubre aún.

        Args:
            pattern_description: Descripción del patrón inseguro.
                  Ejemplo: "RestClient de RestSharp con URL base dinámica"
            code_examples:       Snippets de código C# que muestran el patrón.
            vulnerability_kind:  Tipo de vuln esperado ("SSRF", "SQL_INJECTION", etc.)
            frameworks:          Frameworks relevantes (["aspnetcore", "generic"]).
            timeout_sec:         Timeout para la llamada a Gemini.

        Returns:
            GenerationResult con las reglas generadas y validadas.
        """
        t_start = time.monotonic()

        if not self._gemini.enabled:
            return GenerationResult(
                rules=[],
                pattern_source="pattern_description",
                generation_time_ms=0.0,
                gemini_success=False,
                gemini_error="Gemini deshabilitado — configurar GOOGLE_GEMINI_API_KEY",
            )

        logger.info(
            "RuleGenerator: generando reglas para patrón: '%s...'",
            pattern_description[:60],
        )

        # Obtener IDs existentes para evitar duplicados
        existing_rule_ids = list(self._existing_ids)

        # Construir el prompt
        prompt = self._builder.build_rule_generation_prompt(
            pattern_description=pattern_description,
            code_examples=code_examples or [],
            vulnerability_kind=vulnerability_kind,
            frameworks=frameworks,
            existing_rules=existing_rule_ids[:15],  # Max 15 para no inflar el prompt
        )
        system_prompt = self._builder.get_system_prompt_rule_generation()

        # Llamar a Gemini
        try:
            response = await self._gemini.generate_rule(
                prompt=prompt,
                system_prompt=system_prompt,
                timeout_sec=timeout_sec,
            )
        except Exception as exc:
            logger.error("RuleGenerator: error llamando a Gemini: %s", exc)
            return GenerationResult(
                rules=[],
                pattern_source="pattern_description",
                generation_time_ms=(time.monotonic() - t_start) * 1000,
                gemini_success=False,
                gemini_error=str(exc),
            )

        if not response.get("success"):
            error = response.get("error", "Error desconocido de Gemini")
            logger.warning("RuleGenerator: Gemini retornó error: %s", error)
            return GenerationResult(
                rules=[],
                pattern_source="pattern_description",
                generation_time_ms=(time.monotonic() - t_start) * 1000,
                gemini_success=False,
                gemini_error=error,
            )

        # Parsear y validar las reglas del response
        raw_rules = self._extract_rules_from_response(response)
        generated_rules = self._process_raw_rules(
            raw_rules=raw_rules,
            pattern_source="pattern_description",
            gemini_model=self._gemini.model_name,
        )

        elapsed_ms = (time.monotonic() - t_start) * 1000
        result = GenerationResult(
            rules=generated_rules,
            pattern_source="pattern_description",
            generation_time_ms=elapsed_ms,
            gemini_success=True,
        )

        logger.info(
            "RuleGenerator: %s en %.0f ms",
            result.summary(),
            elapsed_ms,
        )
        return result

    async def generate_from_code_analysis(
        self,
        code_snippet: str,
        file_context: str = "",
        framework:    str = "generic",
        timeout_sec:  float = 60.0,
    ) -> GenerationResult:
        """
        Analiza un snippet de código C# para descubrir patrones inseguros
        y genera reglas SAST para detectarlos.

        Proceso en 2 fases:
          Fase 1: Análisis del código → identificar patrones inseguros
          Fase 2: Generación de reglas para los patrones encontrados

        Args:
            code_snippet: Código C# a analizar (puede ser un método, clase o archivo).
            file_context: Nombre/ruta del archivo (para contexto en el prompt).
            framework:    Framework detectado del proyecto.
            timeout_sec:  Timeout total para ambas fases.

        Returns:
            GenerationResult con las reglas generadas.
        """
        t_start = time.monotonic()

        if not self._gemini.enabled:
            return GenerationResult(
                rules=[],
                pattern_source="code_analysis",
                generation_time_ms=0.0,
                gemini_success=False,
                gemini_error="Gemini deshabilitado",
            )

        logger.info(
            "RuleGenerator: analizando código (%d chars) del archivo '%s'",
            len(code_snippet),
            file_context.split("/")[-1] if file_context else "?",
        )

        # ── Fase 1: Análisis de patrones ──────────────────────────────────────
        analysis_prompt = self._builder.build_pattern_analysis_prompt(
            code_snippet=code_snippet,
            file_context=file_context,
            framework=framework,
        )
        system_prompt_analysis = self._builder.get_system_prompt_pattern_analysis()

        try:
            analysis_response = await self._gemini.analyze_vulnerability(
                prompt=analysis_prompt,
                system_prompt=system_prompt_analysis,
                timeout_sec=timeout_sec / 2,
            )
        except Exception as exc:
            logger.error("RuleGenerator: error en fase de análisis: %s", exc)
            return GenerationResult(
                rules=[],
                pattern_source="code_analysis",
                generation_time_ms=(time.monotonic() - t_start) * 1000,
                gemini_success=False,
                gemini_error=f"Error en análisis: {exc}",
            )

        if not analysis_response.get("success"):
            return GenerationResult(
                rules=[],
                pattern_source="code_analysis",
                generation_time_ms=(time.monotonic() - t_start) * 1000,
                gemini_success=False,
                gemini_error=analysis_response.get("error", "Análisis fallido"),
            )

        # Extraer patrones identificados
        analysis_data = analysis_response.get("analysis", {})
        patterns_found = analysis_data.get("patterns_found", [])

        if not patterns_found:
            logger.info("RuleGenerator: no se encontraron patrones inseguros en el código.")
            return GenerationResult(
                rules=[],
                pattern_source="code_analysis",
                generation_time_ms=(time.monotonic() - t_start) * 1000,
                gemini_success=True,
            )

        logger.info(
            "RuleGenerator: encontrados %d patrones inseguros — generando reglas...",
            len(patterns_found),
        )

        # ── Fase 2: Generación de reglas para los patrones ─────────────────────
        # Convertir patrones a descripción para el generador
        pattern_desc = self._patterns_to_description(patterns_found, framework)
        code_examples = [code_snippet[:500]]  # Ejemplo del código analizado

        return await self.generate_from_pattern(
            pattern_description=pattern_desc,
            code_examples=code_examples,
            frameworks=[framework, "generic"],
            timeout_sec=timeout_sec / 2,
        )

    async def generate_bulk(
        self,
        patterns: list[dict[str, Any]],
        delay_between_sec: float = 1.0,
        timeout_per_pattern: float = 45.0,
    ) -> list[GenerationResult]:
        """
        Genera reglas para múltiples patrones en secuencia.

        Args:
            patterns: Lista de dicts con los campos:
                      - "description" (str, requerido)
                      - "code_examples" (list[str], opcional)
                      - "vulnerability_kind" (str, opcional)
                      - "frameworks" (list[str], opcional)
            delay_between_sec: Pausa entre generaciones (rate limiting).
            timeout_per_pattern: Timeout por cada patrón.

        Returns:
            Lista de GenerationResult en el mismo orden que patterns.
        """
        results: list[GenerationResult] = []

        logger.info(
            "RuleGenerator: generación bulk de %d patrones...",
            len(patterns),
        )

        for i, pattern in enumerate(patterns, 1):
            logger.info(
                "RuleGenerator: procesando patrón %d/%d: '%s...'",
                i, len(patterns),
                pattern.get("description", "?")[:50],
            )

            result = await self.generate_from_pattern(
                pattern_description=pattern.get("description", ""),
                code_examples=pattern.get("code_examples"),
                vulnerability_kind=pattern.get("vulnerability_kind"),
                frameworks=pattern.get("frameworks"),
                timeout_sec=timeout_per_pattern,
            )
            results.append(result)

            # Rate limiting entre llamadas
            if i < len(patterns):
                await asyncio.sleep(delay_between_sec)

        total_valid = sum(r.valid_count for r in results)
        logger.info(
            "RuleGenerator: bulk completado — %d reglas válidas de %d patrones.",
            total_valid, len(patterns),
        )
        return results

    # ─────────────────────────────────────────────────────────────────────────
    #  VALIDACIÓN DE REGLAS
    # ─────────────────────────────────────────────────────────────────────────

    def validate_rule(self, rule_dict: dict[str, Any]) -> ValidationResult:
        """
        Valida una regla contra el schema del engine csharp-sast.

        Valida campos requeridos, tipos, valores permitidos y coherencia
        entre campos (p.ej. un sink debe tener vulnerability, un sanitizer
        debe tener sanitizes, etc.).

        Args:
            rule_dict: Dict con la regla a validar.

        Returns:
            ValidationResult con errores, warnings y correcciones automáticas.
        """
        errors:    list[str] = []
        warnings:  list[str] = []
        auto_fixed: list[str] = []

        rule = dict(rule_dict)  # Copia para posibles auto-fixes

        # ── Campos comunes requeridos ─────────────────────────────────────────
        if not rule.get("id"):
            errors.append("Campo 'id' es requerido.")
        if not rule.get("rule_type"):
            errors.append("Campo 'rule_type' es requerido.")
        if not rule.get("symbol"):
            errors.append("Campo 'symbol' es requerido.")
        if not rule.get("name"):
            warnings.append("Campo 'name' vacío — se recomienda un nombre descriptivo.")
        if not rule.get("description"):
            warnings.append("Campo 'description' vacío — documentar el riesgo.")

        rule_type = rule.get("rule_type", "")
        if rule_type and rule_type not in VALID_RULE_TYPES:
            errors.append(
                f"rule_type '{rule_type}' inválido. "
                f"Valores permitidos: {sorted(VALID_RULE_TYPES)}"
            )
            return ValidationResult(
                is_valid=False,
                rule_type=None,
                errors=errors,
                warnings=warnings,
                auto_fixed=auto_fixed,
            )

        # ── Validación por tipo ───────────────────────────────────────────────
        if rule_type == "sink":
            errors, warnings, auto_fixed = self._validate_sink(
                rule, errors, warnings, auto_fixed
            )
        elif rule_type == "source":
            errors, warnings, auto_fixed = self._validate_source(
                rule, errors, warnings, auto_fixed
            )
        elif rule_type == "sanitizer":
            errors, warnings, auto_fixed = self._validate_sanitizer(
                rule, errors, warnings, auto_fixed
            )

        # ── Validar frameworks ────────────────────────────────────────────────
        frameworks = rule.get("frameworks", [])
        if not frameworks:
            warnings.append("Campo 'frameworks' vacío — añadir ['generic'] mínimamente.")
        else:
            invalid_fw = set(frameworks) - VALID_FRAMEWORKS
            if invalid_fw:
                warnings.append(
                    f"Frameworks desconocidos: {invalid_fw}. "
                    f"Valores válidos: {sorted(VALID_FRAMEWORKS)}"
                )

        # ── Validar tags ──────────────────────────────────────────────────────
        if not rule.get("tags"):
            warnings.append("Campo 'tags' vacío — añadir tags para filtrado.")

        # ── Validar símbolo (formato básico) ──────────────────────────────────
        symbol = rule.get("symbol", "")
        if symbol and "." not in symbol:
            warnings.append(
                f"Symbol '{symbol}' parece no ser un fully qualified name de Roslyn. "
                f"Usar formato: Namespace.Class.Method o Namespace.Class..ctor"
            )

        is_valid = len(errors) == 0
        return ValidationResult(
            is_valid=is_valid,
            rule_type=rule_type,
            errors=errors,
            warnings=warnings,
            auto_fixed=auto_fixed,
        )

    def _validate_sink(
        self,
        rule:       dict[str, Any],
        errors:     list[str],
        warnings:   list[str],
        auto_fixed: list[str],
    ) -> tuple[list[str], list[str], list[str]]:
        """Validación específica para reglas de tipo sink."""

        # vulnerability es requerido
        vuln = rule.get("vulnerability", "")
        if not vuln:
            errors.append("Sink requiere campo 'vulnerability'.")
        elif vuln not in VALID_VULNERABILITY_KINDS:
            errors.append(
                f"vulnerability '{vuln}' inválida. "
                f"Valores válidos: {sorted(VALID_VULNERABILITY_KINDS)}"
            )

        # tainted_args — debe ser lista de ints
        tainted = rule.get("tainted_args")
        if tainted is None:
            warnings.append(
                "Sink sin 'tainted_args' — asumiendo [0] (primer argumento)."
            )
        elif not isinstance(tainted, list):
            errors.append("'tainted_args' debe ser una lista de enteros.")
        elif not all(isinstance(x, int) for x in tainted):
            errors.append("'tainted_args' debe contener solo enteros.")

        # always_vulnerable
        if "always_vulnerable" not in rule:
            warnings.append("Sink sin 'always_vulnerable' — asumiendo False.")

        # confidence (string para sinks)
        conf = rule.get("confidence", "")
        if not conf:
            warnings.append("Sink sin 'confidence' — añadir nivel de confianza.")
        elif isinstance(conf, float):
            # Gemini a veces confunde el formato de sanitizer con sink
            errors.append(
                f"'confidence' para sinks debe ser string ('high', 'medium', etc.), "
                f"no float. Recibido: {conf}"
            )
        elif conf not in VALID_SINK_CONFIDENCES:
            warnings.append(
                f"'confidence' '{conf}' no reconocida. "
                f"Valores: {sorted(VALID_SINK_CONFIDENCES)}"
            )

        # severity
        sev = rule.get("severity", "")
        if not sev:
            warnings.append("Sink sin 'severity' — añadir severidad.")
        elif sev not in VALID_SEVERITIES:
            errors.append(
                f"'severity' '{sev}' inválida. "
                f"Valores: {sorted(VALID_SEVERITIES)}"
            )

        # cwe — formato CWE-NNN
        cwe = rule.get("cwe", "")
        if not cwe:
            warnings.append("Sink sin 'cwe' — añadir el CWE correspondiente.")
        elif not cwe.startswith("CWE-"):
            warnings.append(f"'cwe' '{cwe}' no sigue el formato CWE-NNN.")

        # cvss_base — float [0.0, 10.0]
        cvss = rule.get("cvss_base")
        if cvss is None:
            warnings.append("Sink sin 'cvss_base' — añadir puntuación CVSS v3.1.")
        elif not isinstance(cvss, (int, float)):
            errors.append(f"'cvss_base' debe ser un número, recibido: {type(cvss).__name__}")
        elif not 0.0 <= float(cvss) <= 10.0:
            errors.append(f"'cvss_base' {cvss} fuera del rango [0.0, 10.0].")

        # remediation requerida para sinks
        if not rule.get("remediation"):
            warnings.append("Sink sin 'remediation' — añadir instrucciones de remediación.")

        return errors, warnings, auto_fixed

    def _validate_source(
        self,
        rule:       dict[str, Any],
        errors:     list[str],
        warnings:   list[str],
        auto_fixed: list[str],
    ) -> tuple[list[str], list[str], list[str]]:
        """Validación específica para reglas de tipo source."""

        # taint_label requerido
        taint_label = rule.get("taint_label", "")
        if not taint_label:
            errors.append("Source requiere campo 'taint_label'.")
        elif taint_label not in VALID_TAINT_LABELS:
            errors.append(
                f"'taint_label' '{taint_label}' inválido. "
                f"Valores: {sorted(VALID_TAINT_LABELS)}"
            )

        # severity_multiplier — float [0.0, 2.0]
        mult = rule.get("severity_multiplier")
        if mult is None:
            warnings.append(
                "Source sin 'severity_multiplier' — añadir (1.0 = normal)."
            )
            rule["severity_multiplier"] = 1.0
            auto_fixed.append("severity_multiplier = 1.0 (default)")
        elif not isinstance(mult, (int, float)):
            errors.append(f"'severity_multiplier' debe ser float, recibido: {type(mult).__name__}")
        elif not 0.0 <= float(mult) <= 2.0:
            warnings.append(f"'severity_multiplier' {mult} fuera del rango esperado [0.0, 2.0].")

        # implicit
        if "implicit" not in rule:
            rule["implicit"] = False
            auto_fixed.append("implicit = False (default)")

        # data_format
        data_format = rule.get("data_format", "")
        valid_formats = {"string", "bytes", "stream", "object"}
        if not data_format:
            warnings.append("Source sin 'data_format'.")
        elif data_format not in valid_formats:
            warnings.append(
                f"'data_format' '{data_format}' no estándar. "
                f"Valores: {sorted(valid_formats)}"
            )

        # authentication_context
        auth_ctx = rule.get("authentication_context", "")
        valid_auth = {"any", "authenticated"}
        if not auth_ctx:
            rule["authentication_context"] = "any"
            auto_fixed.append("authentication_context = 'any' (default)")
        elif auth_ctx not in valid_auth:
            warnings.append(
                f"'authentication_context' '{auth_ctx}' no estándar. "
                f"Valores: {sorted(valid_auth)}"
            )

        return errors, warnings, auto_fixed

    def _validate_sanitizer(
        self,
        rule:       dict[str, Any],
        errors:     list[str],
        warnings:   list[str],
        auto_fixed: list[str],
    ) -> tuple[list[str], list[str], list[str]]:
        """Validación específica para reglas de tipo sanitizer."""

        # sanitizes — lista de vulnerability kinds
        sanitizes = rule.get("sanitizes", [])
        if not sanitizes:
            errors.append("Sanitizer requiere campo 'sanitizes' (lista de vulnerabilidades).")
        elif not isinstance(sanitizes, list):
            errors.append("'sanitizes' debe ser una lista.")
        else:
            invalid_vulns = set(sanitizes) - VALID_VULNERABILITY_KINDS
            if invalid_vulns:
                errors.append(
                    f"'sanitizes' contiene vulnerabilities inválidas: {invalid_vulns}. "
                    f"Válidas: {sorted(VALID_VULNERABILITY_KINDS)}"
                )

        # sanitizer_type
        san_type = rule.get("sanitizer_type", "")
        if not san_type:
            warnings.append("Sanitizer sin 'sanitizer_type'.")
        elif san_type not in VALID_SANITIZER_TYPES:
            errors.append(
                f"'sanitizer_type' '{san_type}' inválido. "
                f"Valores: {sorted(VALID_SANITIZER_TYPES)}"
            )

        # confidence — float [0.0, 1.0] para sanitizadores
        conf = rule.get("confidence")
        if conf is None:
            errors.append("Sanitizer requiere 'confidence' como float [0.0, 1.0].")
        elif isinstance(conf, str):
            # Gemini puede confundir el formato de sink (str) con sanitizer (float)
            warnings.append(
                f"'confidence' para sanitizers debe ser float, no string '{conf}'. "
                f"Mapeo automático: high→0.90, medium→0.75, low→0.60"
            )
            conf_map = {"confirmed": 0.98, "high": 0.90, "medium": 0.75, "low": 0.60}
            if conf in conf_map:
                rule["confidence"] = conf_map[conf]
                auto_fixed.append(f"confidence string '{conf}' → float {conf_map[conf]}")
        elif not isinstance(conf, (int, float)):
            errors.append(f"'confidence' debe ser float, recibido: {type(conf).__name__}")
        elif not 0.0 <= float(conf) <= 1.0:
            errors.append(f"'confidence' {conf} fuera del rango [0.0, 1.0].")

        # encoding_context — opcional pero recomendado
        if not rule.get("encoding_context"):
            warnings.append(
                "Sanitizer sin 'encoding_context' — añadir contextos donde sanitiza."
            )

        # limitations — muy recomendado para sanitizadores
        if not rule.get("limitations"):
            warnings.append(
                "Sanitizer sin 'limitations' — documentar cuándo NO sanitiza."
            )

        return errors, warnings, auto_fixed

    # ─────────────────────────────────────────────────────────────────────────
    #  ASIGNACIÓN DE IDs ÚNICOS
    # ─────────────────────────────────────────────────────────────────────────

    def assign_unique_id(self, rule: dict[str, Any]) -> str:
        """
        Asigna un ID único a una regla generada por IA.

        Usa el prefijo GEN- para distinguir de reglas built-in.
        El formato es: GEN-{VULN_PREFIX}-{NNN} con NNN auto-incremental.

        Si la regla ya tiene un ID que no colisiona → lo mantiene.
        Si colisiona → genera uno nuevo con prefijo GEN-.

        Args:
            rule: Dict de la regla a la que asignar ID.

        Returns:
            El ID asignado (también modifica rule["id"] in-place).
        """
        existing_id = rule.get("id", "")

        # Si ya tiene un ID GEN- que no colisiona → mantenerlo
        if existing_id.startswith("GEN-") and existing_id not in self._existing_ids:
            self._existing_ids.add(existing_id)
            return existing_id

        # Si el ID no colisiona y no está vacío → respetar pero prefixar
        if existing_id and existing_id not in self._existing_ids:
            # Mantener el ID sugerido por Gemini si es razonable
            if "-" in existing_id and len(existing_id) < 30:
                self._existing_ids.add(existing_id)
                return existing_id

        # Determinar prefijo según tipo y vulnerabilidad
        rule_type = rule.get("rule_type", "")
        if rule_type == "sink":
            vuln = rule.get("vulnerability", "")
            prefix = _VULN_ID_PREFIX.get(vuln, "GEN-SINK")
        elif rule_type == "source":
            prefix = _SOURCE_ID_PREFIX
        else:
            prefix = _SANITIZER_ID_PREFIX

        # Auto-incrementar el contador para este prefijo
        counter = self._id_counters.get(prefix, 0) + 1
        while True:
            candidate = f"{prefix}-{counter:03d}"
            if candidate not in self._existing_ids:
                self._id_counters[prefix] = counter
                self._existing_ids.add(candidate)
                rule["id"] = candidate
                return candidate
            counter += 1

    # ─────────────────────────────────────────────────────────────────────────
    #  DETECCIÓN DE COLISIONES
    # ─────────────────────────────────────────────────────────────────────────

    def detect_collisions(self, rule: dict[str, Any]) -> list[str]:
        """
        Detecta si la regla colisiona con reglas existentes.

        Una colisión ocurre cuando el mismo símbolo ya está cubierto
        por una regla built-in — la nueva regla puede ser redundante.

        Args:
            rule: Dict de la regla a verificar.

        Returns:
            Lista de IDs de reglas existentes con las que colisiona.
        """
        collisions: list[str] = []
        symbol = rule.get("symbol", "")
        if not symbol:
            return collisions

        # Verificar si el símbolo ya está en alguna regla existente
        for existing_symbol in self._existing_symbols:
            if symbol == existing_symbol:
                collisions.append(f"Symbol exacto ya cubierto: {existing_symbol}")
                break
            # Colisión parcial: prefijo de símbolo similar
            if existing_symbol.startswith(symbol[:40]) and len(symbol) > 20:
                collisions.append(f"Symbol similar ya cubierto: {existing_symbol}")

        return collisions

    # ─────────────────────────────────────────────────────────────────────────
    #  EXPORTACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def export_to_python(
        self,
        generated_rules: list[GeneratedRule],
        output_path:     Path,
        module_name:     str | None = None,
        include_metadata: bool = True,
    ) -> Path:
        """
        Exporta reglas generadas a un archivo .py compatible con el engine.

        El archivo generado sigue exactamente el mismo formato que los
        catálogos built-in (sql_sinks.py, aspnet_sources.py, etc.) y puede
        cargarse como custom rule via RuleLoader(custom_path=output_path.parent).

        Args:
            generated_rules: Lista de GeneratedRule a exportar.
            output_path:     Ruta del archivo .py a crear.
            module_name:     Nombre del módulo (para el docstring).
            include_metadata: Si True, incluye metadata de generación como comentarios.

        Returns:
            Path al archivo creado.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        module_name = module_name or output_path.stem
        valid_rules  = [gr for gr in generated_rules if gr.validation.is_valid]
        rules_dicts  = [gr.rule for gr in valid_rules]

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines: list[str] = [
            f"# =============================================================================",
            f"#  REGLAS GENERADAS POR IA — csharp-sast / {module_name}.py",
            f"#  Generadas: {generated_at}",
            f"#  Reglas: {len(rules_dicts)} ({len([r for r in valid_rules if r.is_production_ready])} listas para producción)",
            f"#",
            f"#  ⚠️  ESTAS REGLAS FUERON GENERADAS POR IA (GEMINI)",
            f"#  Revisar cuidadosamente antes de usar en producción:",
            f"#    1. Verificar que el symbol es un fully qualified name de Roslyn correcto",
            f"#    2. Probar con código C# real para confirmar los findings",
            f"#    3. Verificar que no hay falsos positivos",
            f"#    4. Revisar los campos confidence, severity y cwe",
            f"#",
            f"#  Para cargar estas reglas como custom rules:",
            f"#    from core.rules.rule_loader import RuleLoader",
            f"#    loader = RuleLoader(custom_path=Path('./{output_path.parent.name}'))",
            f"# =============================================================================",
            f"",
            f"from __future__ import annotations",
            f"",
            f"GENERATED_RULES: list[dict] = [",
        ]

        for i, (gr, rule_dict) in enumerate(zip(valid_rules, rules_dicts)):
            if include_metadata:
                lines.append(f"    # ─── {gr.rule_id} — generada por IA (conf_ai={gr.confidence_ai:.2f}) ───")
                if gr.collisions:
                    lines.append(f"    # ⚠️  COLISIÓN DETECTADA: {gr.collisions[0]}")
                if gr.validation.warnings:
                    for w in gr.validation.warnings[:2]:
                        lines.append(f"    # WARN: {w}")
                if gr.validation.auto_fixed:
                    for fix in gr.validation.auto_fixed:
                        lines.append(f"    # AUTO-FIX: {fix}")

            # Serializar la regla como Python dict con indentación correcta
            rule_lines = json.dumps(rule_dict, indent=4, ensure_ascii=False).splitlines()
            # Indentar cada línea con 4 espacios para estar dentro de la lista
            indented = "\n".join("    " + ln for ln in rule_lines)
            comma = "," if i < len(rules_dicts) - 1 else ""
            lines.append(indented + comma)
            lines.append("")

        lines.extend([
            "]",
            "",
            "",
            "def get_rules() -> list[dict]:",
            '    """Retorna las reglas generadas por IA. Requerido por RuleLoader."""',
            "    return GENERATED_RULES",
            "",
            "",
            "def get_rule_ids() -> list[str]:",
            '    """Retorna los IDs de las reglas generadas."""',
            "    return [r['id'] for r in GENERATED_RULES]",
            "",
            "",
            "def get_rules_by_type(rule_type: str) -> list[dict]:",
            '    """Filtra por tipo de regla: sink | source | sanitizer."""',
            "    return [r for r in GENERATED_RULES if r.get('rule_type') == rule_type]",
        ])

        content = "\n".join(lines)

        with output_path.open("w", encoding="utf-8") as f:
            f.write(content)

        logger.info(
            "RuleGenerator: %d reglas exportadas a '%s' (%.1f KB)",
            len(rules_dicts),
            output_path,
            output_path.stat().st_size / 1024,
        )
        return output_path

    def export_to_json(
        self,
        generated_rules:  list[GeneratedRule],
        output_path:      Path,
        include_metadata: bool = True,
        only_valid:       bool = True,
    ) -> Path:
        """
        Exporta reglas generadas a un archivo JSON para revisión manual.

        El JSON incluye la regla + metadata de generación + validación,
        útil para revisión humana antes de decidir si integrar al engine.

        Args:
            generated_rules:  Lista de GeneratedRule a exportar.
            output_path:      Ruta del archivo .json a crear.
            include_metadata: Si True, incluye metadata completa de generación.
            only_valid:       Si True, solo exporta reglas que pasaron validación.

        Returns:
            Path al archivo creado.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        rules_to_export = (
            [gr for gr in generated_rules if gr.validation.is_valid]
            if only_valid
            else generated_rules
        )

        export_data = {
            "schema_version":  "1.0.0",
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "total_rules":     len(rules_to_export),
            "valid_count":     sum(1 for r in rules_to_export if r.validation.is_valid),
            "production_ready": sum(1 for r in rules_to_export if r.is_production_ready),
            "warning": (
                "Estas reglas fueron generadas por IA. "
                "Revisar antes de usar en producción."
            ),
            "rules": [
                gr.to_dict() if include_metadata else {"rule": gr.rule}
                for gr in rules_to_export
            ],
        }

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        logger.info(
            "RuleGenerator: %d reglas exportadas a JSON '%s' (%.1f KB)",
            len(rules_to_export),
            output_path,
            output_path.stat().st_size / 1024,
        )
        return output_path

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS INTERNOS
    # ─────────────────────────────────────────────────────────────────────────

    def _index_existing_rules(self, existing_rules: list[dict[str, Any]]) -> None:
        """Indexa reglas existentes para detección de colisiones e IDs."""
        for rule in existing_rules:
            rule_id = rule.get("id", "")
            symbol  = rule.get("symbol", "")
            if rule_id:
                self._existing_ids.add(rule_id)
                # Inicializar contadores de ID según los prefijos encontrados
                parts = rule_id.split("-")
                if len(parts) >= 3:
                    try:
                        num = int(parts[-1])
                        prefix = "-".join(parts[:-1])
                        current = self._id_counters.get(prefix, 0)
                        if num > current:
                            self._id_counters[prefix] = num
                    except ValueError:
                        pass
            if symbol:
                self._existing_symbols.add(symbol)

        logger.debug(
            "RuleGenerator: indexadas %d reglas existentes (%d símbolos únicos).",
            len(self._existing_ids),
            len(self._existing_symbols),
        )

    def _extract_rules_from_response(
        self,
        response: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Extrae la lista de reglas del response de Gemini.

        Gemini puede retornar:
          - Un array JSON directamente en analysis
          - Un objeto con una clave "rules" o similar
          - Un solo objeto de regla (no lista)
        """
        analysis = response.get("analysis", {})

        # Caso 1: analysis es directamente una lista
        if isinstance(analysis, list):
            return analysis

        # Caso 2: analysis tiene una clave "rules"
        if isinstance(analysis, dict):
            for key in ("rules", "generated_rules", "sink_rules", "items"):
                if key in analysis and isinstance(analysis[key], list):
                    return analysis[key]

            # Caso 3: analysis es un solo objeto de regla
            if "rule_type" in analysis or "symbol" in analysis:
                return [analysis]

        return []

    def _process_raw_rules(
        self,
        raw_rules:      list[dict[str, Any]],
        pattern_source: str,
        gemini_model:   str,
    ) -> list[GeneratedRule]:
        """
        Procesa, valida y asigna IDs a reglas crudas de Gemini.

        Returns:
            Lista de GeneratedRule con validación completa.
        """
        self._generation_counter += 1
        generated_at = datetime.now(timezone.utc).isoformat()
        results: list[GeneratedRule] = []

        for i, raw_rule in enumerate(raw_rules):
            if not isinstance(raw_rule, dict):
                logger.warning(
                    "RuleGenerator: regla %d no es un dict, ignorada: %s",
                    i + 1, type(raw_rule).__name__,
                )
                continue

            # ── Validar primero (antes de asignar ID para no desperdiciar contador)
            validation = self.validate_rule(raw_rule)

            # ── Asignar ID único (aunque sea inválida, para trazabilidad)
            self.assign_unique_id(raw_rule)

            # ── Detectar colisiones con reglas built-in
            collisions = self.detect_collisions(raw_rule)
            if collisions:
                logger.info(
                    "RuleGenerator: regla '%s' colisiona con: %s",
                    raw_rule.get("id", "?"),
                    collisions[0],
                )

            # ── Calcular confidence_ai desde el response de Gemini
            confidence_ai = self._estimate_confidence_ai(raw_rule, validation)

            # ── Crear GeneratedRule
            gen_id = f"{self._generation_counter:06d}-{i+1:03d}"
            gr = GeneratedRule(
                rule=raw_rule,
                generated_at=generated_at,
                gemini_model=gemini_model,
                pattern_source=pattern_source,
                generation_id=gen_id,
                confidence_ai=confidence_ai,
                validation=validation,
                collisions=collisions,
            )
            results.append(gr)

            log_level = logging.INFO if validation.is_valid else logging.WARNING
            logger.log(
                log_level,
                "RuleGenerator: regla %s — %s (col=%d)",
                raw_rule.get("id", "?"),
                validation,
                len(collisions),
            )

        return results

    def _estimate_confidence_ai(
        self,
        rule:       dict[str, Any],
        validation: ValidationResult,
    ) -> float:
        """
        Estima la confianza de la IA en la regla generada.

        Basado en: completitud de campos, ausencia de errores,
        presencia de warnings, y coherencia de la regla.

        Returns:
            Float [0.0, 1.0] — mayor es más confiable.
        """
        confidence = 1.0

        # Reducción por errores de validación
        confidence -= len(validation.errors) * 0.15

        # Reducción por warnings importantes
        confidence -= len(validation.warnings) * 0.05

        # Reducción si el símbolo es sospechoso
        symbol = rule.get("symbol", "")
        if symbol and "." not in symbol:
            confidence -= 0.20  # No parece un fully qualified name

        # Reducción si la descripción es muy corta
        desc = rule.get("description", "")
        if len(desc) < 30:
            confidence -= 0.10

        # Reducción si no tiene remediation (para sinks)
        if rule.get("rule_type") == "sink" and not rule.get("remediation"):
            confidence -= 0.10

        return max(0.0, round(confidence, 2))

    def _patterns_to_description(
        self,
        patterns: list[dict[str, Any]],
        framework: str,
    ) -> str:
        """Convierte los patrones encontrados en el análisis a una descripción."""
        if not patterns:
            return "Patrones inseguros detectados en código C#."

        parts: list[str] = []
        for p in patterns[:5]:  # Max 5 patrones
            vuln_type = p.get("vulnerability_type", "?")
            symbol    = p.get("symbol", "?")
            desc      = p.get("description", "")
            arg_pos   = p.get("argument_position")

            line = f"- {vuln_type} via {symbol}"
            if desc:
                line += f": {desc}"
            if arg_pos is not None:
                line += f" (arg position: {arg_pos})"
            parts.append(line)

        summary = patterns[0].get("summary", "") if patterns else ""
        pattern_text = "\n".join(parts)

        return (
            f"Patrones inseguros detectados en código C# ({framework}):\n\n"
            f"{pattern_text}"
            + (f"\n\nResumen: {summary}" if summary else "")
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  UTILIDADES PÚBLICAS
    # ─────────────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Estadísticas del generador."""
        return {
            "existing_rules_indexed": len(self._existing_ids),
            "existing_symbols_indexed": len(self._existing_symbols),
            "generations_executed": self._generation_counter,
            "id_counters": dict(self._id_counters),
            "gemini_status": self._gemini.get_status(),
        }

    def is_ready(self) -> bool:
        """True si el generador puede ejecutar generaciones (Gemini disponible)."""
        return self._gemini.enabled and not self._gemini.is_circuit_open()

    def load_existing_rules_from_loader(self, rule_loader: Any) -> None:
        """
        Carga las reglas existentes desde el RuleLoader del engine.

        Permite al generador detectar colisiones con TODO el catálogo built-in.

        Args:
            rule_loader: Instancia de RuleLoader con las reglas ya cargadas.
        """
        if not hasattr(rule_loader, "load_all"):
            logger.warning("RuleGenerator: object no es un RuleLoader válido.")
            return

        existing = rule_loader.load_all()
        self._index_existing_rules(existing)
        logger.info(
            "RuleGenerator: indexadas %d reglas del RuleLoader.",
            len(existing),
        )

    def __repr__(self) -> str:
        status = "READY" if self.is_ready() else "NOT READY"
        return (
            f"RuleGenerator({status}, "
            f"existing_rules={len(self._existing_ids)}, "
            f"generations={self._generation_counter})"
        )