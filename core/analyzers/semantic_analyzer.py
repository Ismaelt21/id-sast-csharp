# =============================================================================
#  csharp-sast / core / analyzers / semantic_analyzer.py
# =============================================================================
#
#  ANALIZADOR SEMÁNTICO CON GEMINI — REDUCCIÓN DE FALSOS POSITIVOS
#  ──────────────────────────────────────────────────────────────────
#  Integra Gemini AI para analizar el contexto semántico de las
#  vulnerabilidades detectadas y reducir falsos positivos.
#
#  CUÁNDO SE USA:
#    Después del VulnerabilityClassifier, antes de generar el reporte.
#    Solo analiza los findings de confianza MEDIUM o HIGH (no CONFIRMED
#    ni LOW — los CONFIRMED son definitivos, los LOW ya son bajos).
#
#  QUÉ HACE GEMINI:
#    1. Revisa el contexto completo del método (texto del código)
#       y determina si el taint path es realmente explotable
#    2. Detecta sanitizadores implícitos que el análisis estático no ve:
#         if (!int.TryParse(id, out _)) return BadRequest();
#         → el parámetro está validado aunque TryParse no esté en el catálogo
#    3. Detecta falsos positivos estructurales:
#         var query = "SELECT * FROM Products WHERE Category = " + category;
#         // category viene de una tabla de config en BD, no del usuario
#    4. Enriquece la descripción con contexto específico de C# y .NET
#    5. Sugiere la remediación más adecuada para el patrón concreto detectado
#
#  DISEÑO:
#    • Procesa los findings en batches para respetar los rate limits de Gemini
#    • Cachea resultados por vuln_id para no re-analizar en re-runs
#    • El resultado de Gemini es CONSULTIVO: el engine tiene la última palabra
#    • Si Gemini no está disponible, el analyzer devuelve los findings intactos
#    • Timeout agresivo (30s) para no bloquear el pipeline
#
#  REUTILIZACIÓN DE py-sast:
#    • gemini_client.py   → se reutiliza directamente (API agnóstica al lenguaje)
#    • La lógica de prompts ES NUEVA (contexto específico de C# / .NET)
#
# =============================================================================

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from core.parsers.ast_importer import ParsedCSharpModel
from core.parsers.framework_detector import FrameworkProfile
from core.analyzers.taint_analyzer import TaintConfidence, VulnerabilityKind
from core.analyzers.vulnerability_classifier import (
    ClassifiedVulnerability,
    FindingSource,
    Severity,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  RESULTADO DEL ANÁLISIS DE GEMINI
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GeminiVerdict:
    """Veredicto de Gemini sobre una vulnerabilidad."""
    vuln_id:            str
    is_false_positive:  bool
    confidence_adjusted: TaintConfidence | None  # None = sin cambio
    severity_adjusted:  Severity | None          # None = sin cambio
    reasoning:          str
    enriched_description: str | None
    enriched_remediation: str | None
    suggested_fix:      str | None   # Snippet de código sugerido
    raw_response:       str = ""


@dataclass
class SemanticAnalysisResult:
    """Resultado del análisis semántico completo."""
    vulns_analyzed:     int
    vulns_confirmed:    int    # Gemini confirmó como real
    false_positives:    int    # Gemini marcó como FP
    skipped:            int    # No enviados a Gemini (CONFIRMED o LOW)
    enriched_vulns:     list[ClassifiedVulnerability]
    verdicts:           list[GeminiVerdict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  PROMPT BUILDER PARA C#
# ─────────────────────────────────────────────────────────────────────────────

class CSharpPromptBuilder:
    """
    Construye los prompts de Gemini especializados en análisis de C# y .NET.
    """

    SYSTEM_PROMPT = """Eres un experto en seguridad de aplicaciones .NET (C#) con más de 10 años de experiencia en SAST (Static Application Security Testing) y penetration testing de aplicaciones ASP.NET Core, Entity Framework, y WCF.

Tu tarea es analizar vulnerabilidades detectadas por un motor SAST en código C# y determinar:
1. Si la vulnerabilidad es real o un falso positivo
2. Si el nivel de confianza debe ajustarse
3. Si hay contexto que el análisis estático no pudo ver (sanitizadores implícitos, validaciones, etc.)

REGLAS:
- Responde SIEMPRE en JSON válido con la estructura exacta especificada
- Sé conservador: en caso de duda, mantén la vulnerabilidad como real
- Ten en cuenta las características específicas de C# y .NET:
  * Model binding automático de ASP.NET Core
  * [ApiController] valida automáticamente el ModelState
  * Razor encodea automáticamente las variables (solo Html.Raw es riesgo)
  * Entity Framework usa LINQ con parámetros automáticos (solo FromSqlRaw es riesgo)
  * async/await no desaparece el taint, solo lo traslada a otro thread
- NO marques como falso positivo sin evidencia clara en el código
"""

    def build_vulnerability_prompt(
        self,
        vuln: ClassifiedVulnerability,
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
    ) -> str:
        """
        Construye el prompt para analizar una vulnerabilidad específica.
        Incluye el contexto completo del método y el taint path.
        """
        # Obtener el código del método completo si está disponible
        method_code = self._get_method_code_context(vuln, model)

        # Construir el contexto de los nodos del taint path
        path_context = self._build_path_context(vuln, model)

        prompt = f"""Analiza la siguiente vulnerabilidad detectada en código C# .NET.

## VULNERABILIDAD DETECTADA

**Tipo**: {vuln.vulnerability_kind.value} ({vuln.cwe})
**Severidad calculada**: {vuln.severity.value}
**Confianza del análisis estático**: {vuln.confidence.value}
**Framework**: {profile.primary_framework.value}
**Fuente del análisis**: {vuln.finding_source.value}

**Archivo**: `{vuln.file.split('/')[-1]}:{vuln.sink_line}`
**Método**: `{vuln.class_name}.{vuln.method_name}()`

**Origen del taint**: {vuln.source_label or 'N/A'}
**Sink (destino vulnerable)**: {vuln.sink_label or vuln.code_snippet[:80]}

## TAINT PATH (camino del dato contaminado)
{chr(10).join(vuln.taint_path_summary) or "No disponible (análisis por patrón)"}

## CÓDIGO DEL MÉTODO
```csharp
{method_code}
```

## NODOS DEL ANÁLISIS
{path_context}

## CONTEXTO ADICIONAL
- Está en un loop: {vuln.is_in_loop}
- Sanitizador parcial detectado: {vuln.has_partial_sanitizer}
- Es endpoint público: {vuln.is_entry_point}
- Clase controller: {vuln.class_name and ('Controller' in vuln.class_name)}

---

Responde ÚNICAMENTE con este JSON (sin markdown, sin texto adicional):

{{
  "is_false_positive": false,
  "reasoning": "Explicación breve de por qué es real o FP (máx 200 chars)",
  "confidence_adjusted": null,
  "severity_adjusted": null,
  "enriched_description": "Descripción enriquecida con contexto específico de C# (máx 300 chars)",
  "enriched_remediation": "Remediación específica para este caso concreto (máx 300 chars)",
  "suggested_fix": "Snippet de código corregido en C# (máx 5 líneas, null si no aplica)"
}}

Valores permitidos:
- is_false_positive: true | false
- confidence_adjusted: "confirmed" | "high" | "medium" | "low" | null
- severity_adjusted: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | null
"""
        return prompt

    def build_batch_summary_prompt(
        self,
        vulns: list[ClassifiedVulnerability],
        profile: FrameworkProfile,
    ) -> str:
        """
        Prompt para análisis batch: pide a Gemini que evalúe múltiples findings
        de una vez para optimizar tokens y latencia.
        Usado para findings de baja-media confianza donde el análisis individual
        no justifica el costo de token.
        """
        vuln_list = "\n".join(
            f"{i+1}. [{v.vulnerability_kind.value}] {v.class_name}.{v.method_name}() "
            f"L{v.sink_line}: {v.code_snippet[:60]}"
            for i, v in enumerate(vulns)
        )

        return f"""Eres un experto en seguridad .NET. Revisa estos {len(vulns)} findings de un SAST en código C# ({profile.primary_framework.value}).

FINDINGS:
{vuln_list}

Para cada finding, indica si es probable FP o real. Responde SOLO con JSON:
{{
  "findings": [
    {{"index": 1, "is_likely_fp": false, "reason": "breve"}},
    ...
  ]
}}"""

    def _get_method_code_context(
        self, vuln: ClassifiedVulnerability, model: ParsedCSharpModel
    ) -> str:
        """
        Extrae el código del método como contexto para Gemini.
        Como el modelo semántico no almacena el código fuente completo,
        reconstituimos el contexto desde los nodos semánticos del método.
        """
        if not vuln.method_name:
            return vuln.code_snippet or "// Código no disponible"

        # Buscar el método por nombre
        method = next(
            (m for cls in model.classes for m in cls.methods if m.name == vuln.method_name),
            None,
        )
        if not method:
            return vuln.code_snippet or "// Método no encontrado"

        # Reconstruir contexto desde nodos semánticos del método
        nodes = model.nodes_by_method.get(method.method_id, [])
        nodes_sorted = sorted(nodes, key=lambda n: n.line)

        lines = [f"// {method.signature}"]
        for node in nodes_sorted[:20]:  # Máximo 20 nodos para no exceder tokens
            prefix = ""
            if node.is_known_source:
                prefix = "// [SOURCE] "
            elif node.is_known_sink:
                prefix = "// [SINK ⚠️] "
            elif node.is_known_sanitizer:
                prefix = "// [SANITIZER ✓] "
            lines.append(f"  L{node.line}: {prefix}{node.text[:100]}")

        return "\n".join(lines)

    def _build_path_context(
        self, vuln: ClassifiedVulnerability, model: ParsedCSharpModel
    ) -> str:
        """Construye contexto de los nodos del taint path."""
        if not vuln.original_findings:
            return "N/A"

        context_parts = []
        for finding in vuln.original_findings[:2]:
            if hasattr(finding, "taint_path"):
                for step in finding.taint_path[:5]:
                    context_parts.append(
                        f"- L{step.line} [{step.kind}]: {step.label[:60]}"
                    )

        return "\n".join(context_parts) or "No disponible"


# ─────────────────────────────────────────────────────────────────────────────
#  ANALIZADOR SEMÁNTICO PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class SemanticAnalyzer:
    """
    Analizador semántico con Gemini para reducir falsos positivos.

    Uso:
        analyzer = SemanticAnalyzer(gemini_client)
        result = await analyzer.analyze(vulns, model, profile)
        refined_vulns = result.enriched_vulns
    """

    # Solo analizar findings con estas confianzas (no CONFIRMED ni LOW)
    ANALYZE_CONFIDENCES = {TaintConfidence.HIGH, TaintConfidence.MEDIUM}

    # Máximo de findings por batch
    BATCH_SIZE = 5

    # Timeout por análisis individual (segundos)
    ANALYSIS_TIMEOUT = 30

    # Máximo de findings a enviar a Gemini en total
    MAX_FINDINGS_TO_ANALYZE = 50

    def __init__(
        self,
        gemini_client: Any,  # gemini_client.GeminiClient de py-sast
        enabled: bool = True,
    ) -> None:
        self._client = gemini_client
        self._enabled = enabled
        self._prompt_builder = CSharpPromptBuilder()

    async def analyze(
        self,
        vulns: list[ClassifiedVulnerability],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
    ) -> SemanticAnalysisResult:
        """
        Analiza los findings con Gemini y retorna la lista refinada.

        Flujo:
          1. Separar findings por nivel de análisis necesario
          2. Enviar a Gemini los de confianza MEDIUM/HIGH (no CONFIRMED ni LOW)
          3. Aplicar los veredictos de Gemini al modelo
          4. Retornar la lista unificada con FPs removidos y descripciones enriquecidas
        """
        if not self._enabled or not self._client:
            logger.info("SemanticAnalyzer deshabilitado o sin cliente Gemini. Pasando findings intactos.")
            return SemanticAnalysisResult(
                vulns_analyzed=0,
                vulns_confirmed=len(vulns),
                false_positives=0,
                skipped=len(vulns),
                enriched_vulns=vulns,
            )

        # Separar los que se analizarán de los que se pasan directamente
        to_analyze = [
            v for v in vulns
            if v.confidence in self.ANALYZE_CONFIDENCES
            and not v.is_false_positive_candidate
        ][:self.MAX_FINDINGS_TO_ANALYZE]

        to_pass_directly = [
            v for v in vulns
            if v not in to_analyze
        ]

        logger.info(
            "SemanticAnalyzer: %d findings totales. "
            "Analizando con Gemini: %d. Pasando directamente: %d.",
            len(vulns),
            len(to_analyze),
            len(to_pass_directly),
        )

        if not to_analyze:
            return SemanticAnalysisResult(
                vulns_analyzed=0,
                vulns_confirmed=len(vulns),
                false_positives=0,
                skipped=len(vulns),
                enriched_vulns=vulns,
            )

        # Analizar con Gemini en batches
        verdicts = await self._analyze_in_batches(to_analyze, model, profile)

        # Aplicar veredictos
        enriched_analyzed, confirmed, false_positives = self._apply_verdicts(
            to_analyze, verdicts
        )

        # Combinar resultado final
        enriched_vulns = to_pass_directly + enriched_analyzed

        return SemanticAnalysisResult(
            vulns_analyzed=len(to_analyze),
            vulns_confirmed=confirmed + len(to_pass_directly),
            false_positives=false_positives,
            skipped=len(to_pass_directly),
            enriched_vulns=enriched_vulns,
            verdicts=verdicts,
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  ANÁLISIS EN BATCHES
    # ─────────────────────────────────────────────────────────────────────────

    async def _analyze_in_batches(
        self,
        vulns: list[ClassifiedVulnerability],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
    ) -> list[GeminiVerdict]:
        """Procesa los findings en batches para respetar rate limits."""
        all_verdicts: list[GeminiVerdict] = []

        # Findings CRITICAL y HIGH van individualmente (máxima precisión)
        individual = [v for v in vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        batch_candidates = [v for v in vulns if v not in individual]

        # Análisis individual para CRITICAL/HIGH
        for vuln in individual:
            try:
                verdict = await asyncio.wait_for(
                    self._analyze_single(vuln, model, profile),
                    timeout=self.ANALYSIS_TIMEOUT,
                )
                all_verdicts.append(verdict)
                await asyncio.sleep(0.5)  # Rate limit básico
            except asyncio.TimeoutError:
                logger.warning("Timeout analizando vuln %s. Manteniendo como real.", vuln.vuln_id[:12])
                all_verdicts.append(self._timeout_verdict(vuln))
            except Exception as exc:
                logger.warning("Error Gemini para %s: %s. Manteniendo como real.", vuln.vuln_id[:12], exc)
                all_verdicts.append(self._error_verdict(vuln, str(exc)))

        # Análisis en batch para MEDIUM
        for i in range(0, len(batch_candidates), self.BATCH_SIZE):
            batch = batch_candidates[i:i + self.BATCH_SIZE]
            try:
                batch_verdicts = await asyncio.wait_for(
                    self._analyze_batch(batch, profile),
                    timeout=self.ANALYSIS_TIMEOUT * 2,
                )
                all_verdicts.extend(batch_verdicts)
                await asyncio.sleep(1.0)
            except asyncio.TimeoutError:
                logger.warning("Timeout en batch %d. Manteniendo findings como reales.", i // self.BATCH_SIZE)
                all_verdicts.extend([self._timeout_verdict(v) for v in batch])
            except Exception as exc:
                logger.warning("Error batch Gemini: %s", exc)
                all_verdicts.extend([self._error_verdict(v, str(exc)) for v in batch])

        logger.info(
            "SemanticAnalyzer: %d veredictos de Gemini. FPs: %d.",
            len(all_verdicts),
            sum(1 for v in all_verdicts if v.is_false_positive),
        )
        return all_verdicts

    async def _analyze_single(
        self,
        vuln: ClassifiedVulnerability,
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
    ) -> GeminiVerdict:
        """Analiza un único finding con Gemini."""
        prompt = self._prompt_builder.build_vulnerability_prompt(vuln, model, profile)

        t0 = time.monotonic()
        response_text = await self._call_gemini(prompt)
        elapsed = time.monotonic() - t0

        logger.debug(
            "Gemini respondió en %.1fs para %s [%s]",
            elapsed,
            vuln.vulnerability_kind.value,
            vuln.vuln_id[:12],
        )

        return self._parse_single_verdict(vuln.vuln_id, response_text)

    async def _analyze_batch(
        self,
        vulns: list[ClassifiedVulnerability],
        profile: FrameworkProfile,
    ) -> list[GeminiVerdict]:
        """Analiza múltiples findings en una sola llamada a Gemini."""
        prompt = self._prompt_builder.build_batch_summary_prompt(vulns, profile)
        response_text = await self._call_gemini(prompt)
        return self._parse_batch_verdicts(vulns, response_text)

    # ─────────────────────────────────────────────────────────────────────────
    #  LLAMADA A GEMINI (adaptador al gemini_client.py de py-sast)
    # ─────────────────────────────────────────────────────────────────────────

    async def _call_gemini(self, prompt: str) -> str:
        """
        Llama a Gemini via el cliente reutilizado de py-sast.
        Soporta tanto clientes síncronos como asíncronos.
        """
        try:
            # Intentar llamada asíncrona
            if hasattr(self._client, "generate_async"):
                return await self._client.generate_async(
                    prompt=prompt,
                    system_prompt=CSharpPromptBuilder.SYSTEM_PROMPT,
                    max_tokens=1000,
                    temperature=0.1,  # Baja temperatura para respuestas consistentes
                )
            # Fallback: llamada síncrona en executor
            elif hasattr(self._client, "generate"):
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None,
                    lambda: self._client.generate(
                        prompt=prompt,
                        system_prompt=CSharpPromptBuilder.SYSTEM_PROMPT,
                        max_tokens=1000,
                        temperature=0.1,
                    ),
                )
            else:
                raise RuntimeError("El gemini_client no tiene método generate o generate_async")
        except Exception as exc:
            logger.warning("Error llamando a Gemini: %s", exc)
            raise

    # ─────────────────────────────────────────────────────────────────────────
    #  PARSING DE RESPUESTAS
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_single_verdict(self, vuln_id: str, response_text: str) -> GeminiVerdict:
        """Parsea la respuesta JSON de Gemini para un análisis individual."""
        try:
            # Limpiar markdown si viene envuelto en ```json ... ```
            clean = response_text.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            clean = clean.strip("` \n")

            data = json.loads(clean)

            # Parsear confidence_adjusted
            conf_map = {
                "confirmed": TaintConfidence.CONFIRMED,
                "high":      TaintConfidence.HIGH,
                "medium":    TaintConfidence.MEDIUM,
                "low":       TaintConfidence.LOW,
            }
            conf_raw = data.get("confidence_adjusted")
            confidence_adjusted = conf_map.get(str(conf_raw).lower()) if conf_raw else None

            # Parsear severity_adjusted
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH":     Severity.HIGH,
                "MEDIUM":   Severity.MEDIUM,
                "LOW":      Severity.LOW,
                "INFO":     Severity.INFO,
            }
            sev_raw = data.get("severity_adjusted")
            severity_adjusted = sev_map.get(str(sev_raw).upper()) if sev_raw else None

            return GeminiVerdict(
                vuln_id=vuln_id,
                is_false_positive=bool(data.get("is_false_positive", False)),
                confidence_adjusted=confidence_adjusted,
                severity_adjusted=severity_adjusted,
                reasoning=str(data.get("reasoning", ""))[:300],
                enriched_description=data.get("enriched_description"),
                enriched_remediation=data.get("enriched_remediation"),
                suggested_fix=data.get("suggested_fix"),
                raw_response=response_text[:500],
            )

        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning(
                "No se pudo parsear respuesta de Gemini (vuln %s): %s. Response: %s",
                vuln_id[:12], exc, response_text[:100],
            )
            return GeminiVerdict(
                vuln_id=vuln_id,
                is_false_positive=False,
                confidence_adjusted=None,
                severity_adjusted=None,
                reasoning="Error parseando respuesta de Gemini — manteniendo como real",
                enriched_description=None,
                enriched_remediation=None,
                suggested_fix=None,
                raw_response=response_text[:200],
            )

    def _parse_batch_verdicts(
        self,
        vulns: list[ClassifiedVulnerability],
        response_text: str,
    ) -> list[GeminiVerdict]:
        """Parsea la respuesta batch de Gemini."""
        verdicts: list[GeminiVerdict] = []

        try:
            clean = response_text.strip().strip("`").strip()
            if clean.startswith("json"):
                clean = clean[4:].strip()
            data = json.loads(clean)
            findings_data = data.get("findings", [])

            for fd in findings_data:
                idx = fd.get("index", 0) - 1
                if 0 <= idx < len(vulns):
                    verdicts.append(GeminiVerdict(
                        vuln_id=vulns[idx].vuln_id,
                        is_false_positive=bool(fd.get("is_likely_fp", False)),
                        confidence_adjusted=None,
                        severity_adjusted=None,
                        reasoning=str(fd.get("reason", ""))[:200],
                        enriched_description=None,
                        enriched_remediation=None,
                        suggested_fix=None,
                        raw_response=str(fd),
                    ))

            # Para los que no tuvieron respuesta, añadir verdict por defecto
            responded_ids = {v.vuln_id for v in verdicts}
            for vuln in vulns:
                if vuln.vuln_id not in responded_ids:
                    verdicts.append(self._error_verdict(vuln, "No incluido en respuesta batch"))

        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Error parseando respuesta batch: %s", exc)
            verdicts = [self._error_verdict(v, str(exc)) for v in vulns]

        return verdicts

    # ─────────────────────────────────────────────────────────────────────────
    #  APLICACIÓN DE VEREDICTOS
    # ─────────────────────────────────────────────────────────────────────────

    def _apply_verdicts(
        self,
        vulns: list[ClassifiedVulnerability],
        verdicts: list[GeminiVerdict],
    ) -> tuple[list[ClassifiedVulnerability], int, int]:
        """
        Aplica los veredictos de Gemini a los findings.

        Returns:
            (enriched_vulns, confirmed_count, false_positive_count)
        """
        verdicts_by_id = {v.vuln_id: v for v in verdicts}
        enriched: list[ClassifiedVulnerability] = []
        confirmed = 0
        false_positives = 0

        for vuln in vulns:
            verdict = verdicts_by_id.get(vuln.vuln_id)

            if not verdict:
                enriched.append(vuln)
                confirmed += 1
                continue

            if verdict.is_false_positive:
                logger.info(
                    "Gemini marcó como FP: %s [%s] L%d — %s",
                    vuln.vulnerability_kind.value,
                    vuln.cwe,
                    vuln.sink_line,
                    verdict.reasoning[:80],
                )
                false_positives += 1
                # No añadir a enriched → se filtra del reporte final
                continue

            # Aplicar ajustes de Gemini al finding
            modified_vuln = self._enrich_vuln(vuln, verdict)
            enriched.append(modified_vuln)
            confirmed += 1

        return enriched, confirmed, false_positives

    def _enrich_vuln(
        self,
        vuln: ClassifiedVulnerability,
        verdict: GeminiVerdict,
    ) -> ClassifiedVulnerability:
        """Aplica el enriquecimiento de Gemini al finding."""
        # Actualizar descripción si Gemini la mejoró
        if verdict.enriched_description:
            vuln.description = (
                f"{vuln.description}\n\n"
                f"**Análisis IA**: {verdict.enriched_description}"
            )

        # Actualizar remediación si Gemini la mejoró
        if verdict.enriched_remediation:
            vuln.remediation = verdict.enriched_remediation

        # Añadir el fix sugerido a las referencias si está disponible
        if verdict.suggested_fix:
            vuln.raw_evidence["gemini_suggested_fix"] = verdict.suggested_fix

        # Aplicar ajuste de confianza
        if verdict.confidence_adjusted:
            vuln.confidence = verdict.confidence_adjusted

        # Aplicar ajuste de severidad
        if verdict.severity_adjusted:
            vuln.severity = verdict.severity_adjusted

        vuln.raw_evidence["gemini_reasoning"] = verdict.reasoning
        vuln.raw_evidence["gemini_analyzed"] = True

        return vuln

    # ─────────────────────────────────────────────────────────────────────────
    #  VERDICTS DE FALLBACK
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _timeout_verdict(vuln: ClassifiedVulnerability) -> GeminiVerdict:
        return GeminiVerdict(
            vuln_id=vuln.vuln_id,
            is_false_positive=False,
            confidence_adjusted=None,
            severity_adjusted=None,
            reasoning="Timeout — mantenido como real por precaución",
            enriched_description=None,
            enriched_remediation=None,
            suggested_fix=None,
        )

    @staticmethod
    def _error_verdict(vuln: ClassifiedVulnerability, error: str) -> GeminiVerdict:
        return GeminiVerdict(
            vuln_id=vuln.vuln_id,
            is_false_positive=False,
            confidence_adjusted=None,
            severity_adjusted=None,
            reasoning=f"Error Gemini: {error[:80]} — mantenido como real",
            enriched_description=None,
            enriched_remediation=None,
            suggested_fix=None,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  VERSIÓN SÍNCRONA (para CLI no-async)
# ─────────────────────────────────────────────────────────────────────────────

class SyncSemanticAnalyzer:
    """
    Wrapper síncrono del SemanticAnalyzer para uso en el CLI scanner.py.
    """

    def __init__(self, gemini_client: Any, enabled: bool = True) -> None:
        self._async_analyzer = SemanticAnalyzer(gemini_client, enabled)

    def analyze(
        self,
        vulns: list[ClassifiedVulnerability],
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
    ) -> SemanticAnalysisResult:
        """Versión síncrona del análisis semántico."""
        return asyncio.run(self._async_analyzer.analyze(vulns, model, profile))