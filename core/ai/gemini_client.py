# =============================================================================
#  csharp-sast / core / ai / gemini_client.py
# =============================================================================
#
#  CLIENTE GEMINI PARA CSHARP-SAST
#  ──────────────────────────────────
#  Adaptación del gemini_client.py de py-sast con extensiones específicas
#  para el análisis de C# y .NET:
#
#  REUTILIZACIÓN DE py-sast:
#    • Conexión y configuración base de Google Gemini API
#    • Circuit breaker (MAX_CONSECUTIVE_FAILURES)
#    • Extracción de JSON (_extract_json con parser incremental)
#    • Validación de respuesta (validate_response)
#    • Fallback seguro (_fallback_response)
#    • Healthcheck con timeout (generation_config)
#
#  EXTENSIONES ESPECÍFICAS DE C#:
#    • generate() y generate_async() — interfaz unificada usada por
#      SemanticAnalyzer y RuleGenerator sin conocer el cliente
#    • analyze_vulnerability() — análisis estructurado de una vuln C#
#    • generate_rule() — generación de reglas SAST nuevas
#    • batch_analyze() — análisis de múltiples findings eficientemente
#    • Soporte async nativo (asyncio) para el pipeline async del engine
#    • Configuración de temperatura por tipo de tarea
#
#  RESPONSABILIDADES:
#    Este módulo NO construye prompts — eso es de csharp_prompt_builder.py.
#    Solo: Prompt → Gemini API → JSON limpio / texto estructurado
#
# =============================================================================

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# Importación defensiva de la SDK de Google — el engine funciona sin ella
try:
    from google import genai
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False
    logger.warning(
        "google-generativeai no está instalado. "
        "El análisis con Gemini estará deshabilitado. "
        "Instalar con: pip install google-generativeai"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────────────────────

# Importación defensiva de Settings — si no existe, usamos defaults
try:
    from config.settings import Settings

    _GEMINI_API_KEY  = getattr(Settings, "GOOGLE_GEMINI_API_KEY", "")
    _GEMINI_MODEL    = getattr(Settings, "GEMINI_MODEL", "gemini-1.5-pro")
    _USE_GEMINI      = getattr(Settings, "USE_GEMINI", True)
    _DEBUG           = getattr(Settings, "DEBUG", False)
except ImportError:
    import os
    _GEMINI_API_KEY  = os.getenv("GOOGLE_GEMINI_API_KEY", "")
    _GEMINI_MODEL    = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
    _USE_GEMINI      = bool(_GEMINI_API_KEY)
    _DEBUG           = os.getenv("DEBUG", "false").lower() == "true"


# ─────────────────────────────────────────────────────────────────────────────
#  TEMPERATURAS POR TIPO DE TAREA
#  Menor temperatura → más determinista y consistente
#  Mayor temperatura → más creativo y variado
# ─────────────────────────────────────────────────────────────────────────────

TEMPERATURE_VULNERABILITY_ANALYSIS = 0.1  # Análisis de seguridad: muy determinista
TEMPERATURE_RULE_GENERATION        = 0.3  # Generación de reglas: algo creativo
TEMPERATURE_FALSE_POSITIVE_CHECK   = 0.1  # Verificación de FP: determinista
TEMPERATURE_BATCH_ANALYSIS         = 0.2  # Análisis batch: equilibrado

MAX_TOKENS_VULN_ANALYSIS    = 1500
MAX_TOKENS_RULE_GENERATION  = 2000
MAX_TOKENS_BATCH            = 2000
MAX_TOKENS_HEALTHCHECK      = 5


# ─────────────────────────────────────────────────────────────────────────────
#  CLIENTE GEMINI
# ─────────────────────────────────────────────────────────────────────────────

class GeminiClient:
    """
    Cliente Gemini para el engine SAST de C#.

    Reutiliza la lógica core de py-sast (circuit breaker, JSON extraction,
    fallback) y añade métodos async y especializados para C#.

    Uso:
        client = GeminiClient()

        # Análisis sync (compatible con código no-async)
        result = client.analyze(prompt, system_prompt)

        # Análisis async (para el pipeline async del engine)
        result = await client.generate_async(prompt, system_prompt)

        # Análisis estructurado de vulnerabilidad C#
        verdict = await client.analyze_vulnerability(vuln, model, profile)

        # Generación de regla nueva
        rule = await client.generate_rule(pattern, examples)
    """

    MAX_CONSECUTIVE_FAILURES = 5

    def __init__(
        self,
        api_key:    str | None = None,
        model_name: str | None = None,
        enabled:    bool | None = None,
    ) -> None:
        """
        Args:
            api_key:    API key de Google Gemini. Si None, usa Settings.
            model_name: Nombre del modelo Gemini. Si None, usa Settings.
            enabled:    Forzar habilitado/deshabilitado. Si None, auto-detecta.
        """
        self.model_name = model_name or _GEMINI_MODEL
        self._api_key   = api_key or _GEMINI_API_KEY
        self.model      = None
        self._consecutive_failures = 0

        # Determinar si está habilitado
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = (
                _USE_GEMINI
                and bool(self._api_key)
                and _GENAI_AVAILABLE
            )

        if self.enabled:
            self._initialize()
        else:
            reason = (
                "google-generativeai no instalado" if not _GENAI_AVAILABLE
                else "USE_GEMINI=False" if not _USE_GEMINI
                else "API key no configurada"
            )
            logger.info("GeminiClient deshabilitado: %s", reason)

    # ─────────────────────────────────────────────────────────────────────────
    #  INICIALIZACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _initialize(self) -> None:
        """Inicializa la conexión con la API de Gemini."""
        try:
            genai.configure(api_key=self._api_key)
            self.model = genai.GenerativeModel(self.model_name)
            logger.info("GeminiClient: modelo inicializado: %s", self.model_name)
        except Exception as exc:
            logger.error("GeminiClient: error de inicialización: %s", exc)
            self.enabled = False

    # ─────────────────────────────────────────────────────────────────────────
    #  INTERFAZ PRINCIPAL SYNC (reutilizada de py-sast)
    # ─────────────────────────────────────────────────────────────────────────

    def analyze(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> dict[str, Any]:
        """
        Ejecuta análisis IA contra Gemini (versión síncrona).
        Reutilizado de py-sast — comportamiento idéntico.

        Returns:
            Dict con keys: success, source, model, analysis, [raw_response]
        """
        if not self.enabled:
            return self._fallback_response("Gemini deshabilitado")

        if self.is_circuit_open():
            return self._fallback_response(
                f"Circuit breaker abierto después de "
                f"{self._consecutive_failures} fallos consecutivos. "
                f"Llamar reset_circuit_breaker() para reintentar."
            )

        try:
            full_prompt = f"SYSTEM:\n{system_prompt}\n\nUSER:\n{prompt}"
            response    = self.model.generate_content(full_prompt)
            raw_text    = response.text.strip()
            parsed_json = self._extract_json(raw_text)

            if not parsed_json:
                self._record_failure()
                return self._fallback_response(
                    "Respuesta JSON inválida",
                    raw_text if _DEBUG else None,
                )

            self._consecutive_failures = 0  # Reset en éxito

            result: dict[str, Any] = {
                "success":  True,
                "source":   "gemini",
                "model":    self.model_name,
                "analysis": parsed_json,
            }
            if _DEBUG:
                result["raw_response"] = raw_text

            return result

        except Exception as exc:
            self._record_failure()
            logger.warning("GeminiClient: error en analyze(): %s", exc)
            return self._fallback_response(str(exc))

    def generate(
        self,
        prompt:        str,
        system_prompt: str = "",
        max_tokens:    int = 1000,
        temperature:   float = 0.1,
    ) -> str:
        """
        Genera texto desde Gemini (interfaz unificada sync).
        Usada por SemanticAnalyzer.analyze() y RuleGenerator.

        Returns:
            String con la respuesta de Gemini, o "" en caso de error.
        """
        if not self.enabled or self.is_circuit_open():
            return ""

        try:
            full_prompt = (
                f"SYSTEM:\n{system_prompt}\n\nUSER:\n{prompt}"
                if system_prompt
                else prompt
            )
            response = self.model.generate_content(
                full_prompt,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=temperature,
                ),
            )
            self._consecutive_failures = 0
            return response.text.strip()

        except Exception as exc:
            self._record_failure()
            logger.warning("GeminiClient: error en generate(): %s", exc)
            return ""

    # ─────────────────────────────────────────────────────────────────────────
    #  INTERFAZ ASYNC (extensión para C#)
    # ─────────────────────────────────────────────────────────────────────────

    async def generate_async(
        self,
        prompt:        str,
        system_prompt: str = "",
        max_tokens:    int = 1000,
        temperature:   float = 0.1,
    ) -> str:
        """
        Genera texto desde Gemini (interfaz async).
        Usada por SemanticAnalyzer.analyze() en el pipeline async del engine.

        Internamente delega al executor del event loop para no bloquear
        (la SDK de Google es síncrona en la versión estable).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.generate(prompt, system_prompt, max_tokens, temperature),
        )

    async def analyze_async(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> dict[str, Any]:
        """
        Versión async de analyze() para el pipeline async del engine.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.analyze(prompt, system_prompt),
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  MÉTODOS ESPECIALIZADOS PARA C#
    # ─────────────────────────────────────────────────────────────────────────

    async def analyze_vulnerability(
        self,
        prompt:      str,
        system_prompt: str,
        timeout_sec: float = 30.0,
    ) -> dict[str, Any]:
        """
        Analiza una vulnerabilidad C# específica con Gemini.

        Especializado para el SemanticAnalyzer — usa temperatura baja
        y max_tokens alto para respuestas detalladas.

        Args:
            prompt:       Prompt construido por CSharpPromptBuilder.
            system_prompt: System prompt de contexto C#/.NET.
            timeout_sec:  Timeout para evitar bloqueos en análisis largos.

        Returns:
            Dict con: success, analysis (con is_false_positive, reasoning, etc.)
        """
        if not self.enabled:
            return self._fallback_response("Gemini deshabilitado")

        if self.is_circuit_open():
            return self._fallback_response("Circuit breaker abierto")

        try:
            result = await asyncio.wait_for(
                self.analyze_async(prompt, system_prompt),
                timeout=timeout_sec,
            )
            return result

        except asyncio.TimeoutError:
            logger.warning(
                "GeminiClient: timeout (%.0fs) en analyze_vulnerability",
                timeout_sec,
            )
            return self._fallback_response(
                f"Timeout después de {timeout_sec}s — mantenido como real"
            )
        except Exception as exc:
            self._record_failure()
            return self._fallback_response(str(exc))

    async def generate_rule(
        self,
        prompt:        str,
        system_prompt: str,
        timeout_sec:   float = 45.0,
    ) -> dict[str, Any]:
        """
        Genera una nueva regla SAST para C# con Gemini.

        Especializado para RuleGenerator — usa temperatura más alta
        para generar reglas creativas y diversas, con max_tokens alto.

        Args:
            prompt:       Prompt de generación de regla construido por RuleGenerator.
            system_prompt: System prompt de contexto de reglas SAST.
            timeout_sec:  Timeout para generaciones complejas.

        Returns:
            Dict con la regla generada o fallback.
        """
        if not self.enabled:
            return self._fallback_response("Gemini deshabilitado")

        if self.is_circuit_open():
            return self._fallback_response("Circuit breaker abierto")

        try:
            loop   = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: self._generate_rule_sync(prompt, system_prompt),
                ),
                timeout=timeout_sec,
            )
            return result

        except asyncio.TimeoutError:
            logger.warning(
                "GeminiClient: timeout (%.0fs) en generate_rule", timeout_sec
            )
            return self._fallback_response("Timeout en generación de regla")
        except Exception as exc:
            self._record_failure()
            return self._fallback_response(str(exc))

    def _generate_rule_sync(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> dict[str, Any]:
        """Lógica síncrona de generate_rule para el executor."""
        full_prompt = f"SYSTEM:\n{system_prompt}\n\nUSER:\n{prompt}"
        try:
            response = self.model.generate_content(
                full_prompt,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=MAX_TOKENS_RULE_GENERATION,
                    temperature=TEMPERATURE_RULE_GENERATION,
                ),
            )
            raw_text    = response.text.strip()
            parsed_json = self._extract_json(raw_text)

            if not parsed_json:
                self._record_failure()
                return self._fallback_response(
                    "JSON de regla inválido",
                    raw_text if _DEBUG else None,
                )

            self._consecutive_failures = 0
            result: dict[str, Any] = {
                "success":  True,
                "source":   "gemini",
                "model":    self.model_name,
                "analysis": parsed_json,
            }
            if _DEBUG:
                result["raw_response"] = raw_text
            return result

        except Exception as exc:
            self._record_failure()
            return self._fallback_response(str(exc))

    async def batch_analyze(
        self,
        prompts:       list[tuple[str, str]],  # [(prompt, system_prompt), ...]
        timeout_sec:   float = 60.0,
        delay_between: float = 0.5,
    ) -> list[dict[str, Any]]:
        """
        Analiza múltiples prompts en secuencia respetando rate limits.

        Args:
            prompts:       Lista de (prompt, system_prompt) a analizar.
            timeout_sec:   Timeout total para el batch completo.
            delay_between: Pausa entre llamadas (segundos) para rate limiting.

        Returns:
            Lista de resultados en el mismo orden que prompts.
            Los que fallan retornan fallback_response.
        """
        if not self.enabled:
            return [self._fallback_response("Gemini deshabilitado")] * len(prompts)

        results: list[dict[str, Any]] = []
        t_start = time.monotonic()

        for i, (prompt, system_prompt) in enumerate(prompts):
            # Verificar timeout total
            if time.monotonic() - t_start > timeout_sec:
                logger.warning(
                    "GeminiClient: batch timeout en item %d/%d",
                    i + 1, len(prompts),
                )
                # Rellenar el resto con fallbacks
                remaining = len(prompts) - len(results)
                results.extend([
                    self._fallback_response("Batch timeout")
                ] * remaining)
                break

            try:
                result = await self.analyze_async(prompt, system_prompt)
                results.append(result)

                # Rate limiting entre llamadas
                if i < len(prompts) - 1:
                    await asyncio.sleep(delay_between)

            except Exception as exc:
                logger.warning(
                    "GeminiClient: error en batch item %d: %s", i + 1, exc
                )
                results.append(self._fallback_response(str(exc)))

        logger.info(
            "GeminiClient: batch completado — %d/%d exitosos en %.1fs",
            sum(1 for r in results if r.get("success")),
            len(prompts),
            time.monotonic() - t_start,
        )
        return results

    # ─────────────────────────────────────────────────────────────────────────
    #  JSON EXTRACTION (reutilizado de py-sast con corrección #1)
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        """
        Extrae el primer objeto JSON válido del texto.

        Corrección #1 de py-sast: parser incremental en lugar de regex greedy.
        Encuentra el primer '{' y avanza con contador de profundidad para
        encontrar el cierre correcto.
        """
        # Intento directo (respuesta limpia)
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Eliminar bloques de código markdown si los hay
        cleaned = text
        if "```json" in text:
            cleaned = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            cleaned = text.split("```")[1].split("```")[0].strip()

        try:
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            pass

        # Búsqueda incremental del primer JSON completo
        start = text.find("{")
        if start == -1:
            return None

        depth = 0
        for i, char in enumerate(text[start:], start=start):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start: i + 1]
                    try:
                        return json.loads(candidate)
                    except (json.JSONDecodeError, ValueError):
                        next_start = text.find("{", i + 1)
                        if next_start == -1:
                            return None
                        start = next_start
                        depth = 0

        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  VALIDACIÓN (reutilizado de py-sast)
    # ─────────────────────────────────────────────────────────────────────────

    def validate_response(self, analysis: dict[str, Any]) -> bool:
        """
        Valida estructura mínima de la respuesta de Gemini.
        Reutilizado de py-sast — campos requeridos mínimos.
        """
        required_fields = [
            "vulnerability_detected",
            "classification",
            "confidence",
        ]
        return all(field in analysis for field in required_fields)

    def validate_csharp_response(self, analysis: dict[str, Any]) -> bool:
        """
        Validación extendida específica para respuestas de análisis C#.
        El SemanticAnalyzer usa este esquema más completo.
        """
        required_csharp_fields = [
            "is_false_positive",
            "reasoning",
            "confidence_adjusted",
        ]
        return all(field in analysis for field in required_csharp_fields)

    def validate_rule_response(self, analysis: dict[str, Any]) -> bool:
        """
        Validación para respuestas de generación de reglas.
        El RuleGenerator espera estos campos.
        """
        required_rule_fields = [
            "id",
            "rule_type",
            "symbol",
            "vulnerability",
            "description",
            "remediation",
        ]
        return all(field in analysis for field in required_rule_fields)

    # ─────────────────────────────────────────────────────────────────────────
    #  SAFE ANALYZE (reutilizado de py-sast)
    # ─────────────────────────────────────────────────────────────────────────

    def safe_analyze(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> dict[str, Any]:
        """
        Wrapper seguro con validación de esquema (sync).
        Reutilizado de py-sast.
        """
        result = self.analyze(prompt, system_prompt)

        if not result["success"]:
            return result

        analysis = result.get("analysis", {})
        if not self.validate_response(analysis):
            return self._fallback_response(
                "Esquema de análisis inválido",
                result.get("raw_response"),
            )

        return result

    async def safe_analyze_async(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> dict[str, Any]:
        """Versión async de safe_analyze."""
        result = await self.analyze_async(prompt, system_prompt)

        if not result["success"]:
            return result

        analysis = result.get("analysis", {})
        if not self.validate_response(analysis):
            return self._fallback_response(
                "Esquema de análisis inválido",
                result.get("raw_response"),
            )

        return result

    # ─────────────────────────────────────────────────────────────────────────
    #  FALLBACK (reutilizado de py-sast con corrección #2)
    # ─────────────────────────────────────────────────────────────────────────

    def _fallback_response(
        self,
        reason:       str,
        raw_response: str | None = None,
    ) -> dict[str, Any]:
        """
        Respuesta segura cuando Gemini no está disponible.
        Corrección #2 de py-sast: raw_response solo en DEBUG.
        """
        response: dict[str, Any] = {
            "success": False,
            "source":  "fallback",
            "error":   reason,
            "analysis": {
                "vulnerability_detected": False,
                "classification":         "UNKNOWN",
                "confidence":             0.0,
                "reasoning":              reason,
                # Campos específicos para C# (SemanticAnalyzer)
                "is_false_positive":      False,
                "confidence_adjusted":    None,
                "severity_adjusted":      None,
                "enriched_description":   None,
                "enriched_remediation":   None,
                "suggested_fix":          None,
            },
        }
        if _DEBUG and raw_response:
            response["raw_response"] = raw_response
        return response

    # ─────────────────────────────────────────────────────────────────────────
    #  CIRCUIT BREAKER (reutilizado de py-sast con corrección #4)
    # ─────────────────────────────────────────────────────────────────────────

    def _record_failure(self) -> None:
        """Registra un fallo consecutivo."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
            logger.warning(
                "GeminiClient: circuit breaker ABIERTO después de %d fallos. "
                "Llamar reset_circuit_breaker() para reintentar.",
                self._consecutive_failures,
            )

    def reset_circuit_breaker(self) -> None:
        """Resetea el circuit breaker manualmente."""
        self._consecutive_failures = 0
        logger.info("GeminiClient: circuit breaker reseteado.")

    def is_circuit_open(self) -> bool:
        """True si el circuit breaker está abierto."""
        return self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES

    # ─────────────────────────────────────────────────────────────────────────
    #  HEALTHCHECK (reutilizado de py-sast con corrección #3)
    # ─────────────────────────────────────────────────────────────────────────

    def healthcheck(self) -> bool:
        """
        Verifica disponibilidad de Gemini.
        Corrección #3 de py-sast: generation_config con max_output_tokens mínimo.
        """
        if not self.enabled:
            return False

        try:
            response = self.model.generate_content(
                "Reply ONLY with the word: OK",
                generation_config=genai.GenerationConfig(
                    max_output_tokens=MAX_TOKENS_HEALTHCHECK,
                    temperature=0.0,
                ),
            )
            ok = "OK" in response.text
            logger.debug("GeminiClient: healthcheck %s", "OK" if ok else "FAIL")
            return ok

        except Exception as exc:
            logger.warning("GeminiClient: healthcheck fallido: %s", exc)
            return False

    async def healthcheck_async(self) -> bool:
        """Versión async del healthcheck."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.healthcheck)

    # ─────────────────────────────────────────────────────────────────────────
    #  STATUS
    # ─────────────────────────────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Estado completo del cliente Gemini."""
        return {
            "enabled":                self.enabled,
            "model":                  self.model_name,
            "provider":               "google_gemini",
            "circuit_breaker_open":   self.is_circuit_open(),
            "consecutive_failures":   self._consecutive_failures,
            "max_failures_threshold": self.MAX_CONSECUTIVE_FAILURES,
            "genai_sdk_available":    _GENAI_AVAILABLE,
            "debug_mode":             _DEBUG,
        }

    def __repr__(self) -> str:
        status = "ENABLED" if self.enabled else "DISABLED"
        cb     = " [CB:OPEN]" if self.is_circuit_open() else ""
        return f"GeminiClient({status}, model={self.model_name}{cb})"