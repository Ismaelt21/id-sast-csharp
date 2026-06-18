# =============================================================================
#  csharp-sast / core / parsers / roslyn_client.py
# =============================================================================
#
#  CLIENTE HTTP DEL ROSLYN BRIDGE
#  ────────────────────────────────
#  Encapsula toda la comunicación entre el engine Python y el bridge .NET.
#
#  RESPONSABILIDADES:
#    • Enviar archivos .cs al endpoint POST /analyze del bridge
#    • Verificar disponibilidad del bridge (GET /health)
#    • Manejar compresión GZip (el bridge comprime respuestas > 512 KB)
#    • Reintentos con backoff exponencial para fallos transitorios
#    • Timeout configurable por análisis
#    • Arrancar/detener el proceso del bridge si no está corriendo
#
#  FLUJO TÍPICO:
#    client = RoslynClient()
#    await client.ensure_bridge_running()
#    result_json = await client.analyze(files=["UserController.cs"])
#    # result_json es el RoslynExportRoot deserializado como dict Python
#
#  MANEJO DE ERRORES:
#    BridgeNotAvailableError  → bridge no responde (no instalado / crasheó)
#    BridgeTimeoutError       → análisis excedió el timeout
#    BridgeAnalysisError      → error interno del bridge (400/500)
#
# =============================================================================

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  EXCEPCIONES
# ─────────────────────────────────────────────────────────────────────────────

class BridgeNotAvailableError(RuntimeError):
    """El Roslyn Bridge no está disponible (no arrancó o no responde)."""


class BridgeTimeoutError(RuntimeError):
    """El análisis excedió el timeout configurado."""


class BridgeAnalysisError(RuntimeError):
    """El bridge retornó un error HTTP (400 / 500)."""
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RoslynClientConfig:
    """Configuración del cliente HTTP del bridge."""

    # URL base del bridge (configurable vía env ROSLYN_BRIDGE_URL)
    bridge_url: str = field(
        default_factory=lambda: os.getenv("ROSLYN_BRIDGE_URL", "http://localhost:5100")
    )

    # Timeout del análisis en segundos (el bridge tiene su propio timeout)
    analysis_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("ROSLYN_ANALYSIS_TIMEOUT", "300"))
    )

    # Timeout para el health check
    health_check_timeout_seconds: int = 10

    # Máximo de reintentos en fallos transitorios (503, timeout de conexión)
    max_retries: int = 3

    # Backoff base en segundos entre reintentos
    retry_backoff_seconds: float = 2.0

    # Ruta al ejecutable del bridge (para arrancarlo automáticamente)
    bridge_executable: str | None = field(
        default_factory=lambda: os.getenv("ROSLYN_BRIDGE_EXE")
    )

    # Si True, intenta arrancar el bridge si no está corriendo
    auto_start_bridge: bool = True

    # Máximo de archivos por request (coincide con el límite del bridge)
    max_files_per_request: int = 500

    # Si True, incluye nodos sin símbolo resuelto en el export (más verboso)
    include_unresolved: bool = False


# ─────────────────────────────────────────────────────────────────────────────
#  CLIENTE PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class RoslynClient:
    """
    Cliente HTTP asíncrono para el Roslyn Bridge.

    Uso típico:
        async with RoslynClient() as client:
            result = await client.analyze(["path/to/file.cs"])
    """

    def __init__(self, config: RoslynClientConfig | None = None) -> None:
        self._config = config or RoslynClientConfig()
        self._session: aiohttp.ClientSession | None = None
        self._bridge_process: subprocess.Popen | None = None
        self._bridge_started_by_us = False

    # ─────────────────────────────────────────────────────────────────────────
    #  CONTEXT MANAGER
    # ─────────────────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "RoslynClient":
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=4),
            timeout=aiohttp.ClientTimeout(
                total=self._config.analysis_timeout_seconds + 30,
                connect=10,
            ),
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()
        if self._bridge_started_by_us and self._bridge_process:
            logger.info("Deteniendo el Roslyn Bridge que iniciamos.")
            self._bridge_process.terminate()
            try:
                self._bridge_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._bridge_process.kill()

    # ─────────────────────────────────────────────────────────────────────────
    #  HEALTH CHECK
    # ─────────────────────────────────────────────────────────────────────────

    async def health_check(self) -> dict[str, Any]:
        """
        Verifica que el bridge está operativo.
        Retorna el dict del HealthResponse del bridge.
        Lanza BridgeNotAvailableError si no responde.
        """
        url = f"{self._config.bridge_url}/health"
        try:
            async with self._get_session().get(
                url,
                timeout=aiohttp.ClientTimeout(total=self._config.health_check_timeout_seconds),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    logger.debug("Bridge health OK: %s", data.get("status"))
                    return data
                raise BridgeNotAvailableError(
                    f"Bridge health check retornó HTTP {resp.status}"
                )
        except aiohttp.ClientConnectorError as exc:
            raise BridgeNotAvailableError(
                f"No se puede conectar al Roslyn Bridge en {url}: {exc}"
            ) from exc

    async def is_available(self) -> bool:
        """Retorna True si el bridge está disponible, False si no."""
        try:
            await self.health_check()
            return True
        except (BridgeNotAvailableError, aiohttp.ClientError, asyncio.TimeoutError):
            return False

    # ─────────────────────────────────────────────────────────────────────────
    #  ARRANQUE AUTOMÁTICO DEL BRIDGE
    # ─────────────────────────────────────────────────────────────────────────

    async def ensure_bridge_running(self) -> None:
        """
        Verifica que el bridge está disponible.
        Si no lo está y auto_start_bridge=True, intenta arrancarlo.
        Lanza BridgeNotAvailableError si no se puede levantar.
        """
        if await self.is_available():
            logger.debug("Roslyn Bridge disponible en %s", self._config.bridge_url)
            return

        if not self._config.auto_start_bridge:
            raise BridgeNotAvailableError(
                f"Roslyn Bridge no disponible en {self._config.bridge_url}. "
                "Inícialo manualmente o configura auto_start_bridge=True."
            )

        await self._start_bridge_process()

    async def _start_bridge_process(self) -> None:
        """Arranca el proceso del bridge y espera a que responda al health check."""
        executable = self._config.bridge_executable
        if not executable:
            # Buscar el binario en rutas convencionales del proyecto
            candidates = [
                Path(__file__).parents[3] / "roslyn_bridge" / "bin" / "Release" / "net8.0" / "RoslynBridge",
                Path(__file__).parents[3] / "roslyn_bridge" / "bin" / "Debug" / "net8.0" / "RoslynBridge",
                Path("roslyn_bridge/bin/Release/net8.0/RoslynBridge"),
            ]
            for candidate in candidates:
                if candidate.exists():
                    executable = str(candidate)
                    break

            if not executable:
                raise BridgeNotAvailableError(
                    "No se encontró el ejecutable del Roslyn Bridge. "
                    "Compílalo con 'dotnet publish' o configura ROSLYN_BRIDGE_EXE."
                )

        logger.info("Arrancando Roslyn Bridge: %s", executable)
        port = self._extract_port()

        try:
            executable_path = Path(executable).resolve()
            self._bridge_process = subprocess.Popen(
                [str(executable_path)],
                cwd=str(executable_path.parent),
                env={**os.environ, "ROSLYN_BRIDGE_PORT": str(port)},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._bridge_started_by_us = True
        except (OSError, PermissionError) as exc:
            raise BridgeNotAvailableError(
                f"No se pudo arrancar el bridge: {exc}"
            ) from exc

        # Esperar hasta 30 segundos a que responda al health check
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self._bridge_process.poll() is not None:
                stderr = self._bridge_process.stderr.read().decode(errors="replace")
                raise BridgeNotAvailableError(
                    f"El bridge terminó inesperadamente. Stderr: {stderr[:500]}"
                )
            if await self.is_available():
                logger.info("Roslyn Bridge arrancado y listo en %s", self._config.bridge_url)
                return
            await asyncio.sleep(1.0)

        raise BridgeNotAvailableError(
            "El bridge no respondió al health check en 30 segundos."
        )

    def _extract_port(self) -> int:
        """Extrae el puerto de la URL configurada."""
        try:
            return int(self._config.bridge_url.split(":")[-1])
        except (ValueError, IndexError):
            return 5100

    # ─────────────────────────────────────────────────────────────────────────
    #  ANÁLISIS PRINCIPAL
    # ─────────────────────────────────────────────────────────────────────────

    async def analyze(
        self,
        files: list[str],
        reference_assemblies: list[str] | None = None,
        language_version: str | None = None,
        include_unresolved: bool | None = None,
    ) -> dict[str, Any]:
        """
        Envía archivos .cs al bridge para análisis semántico.

        Args:
            files: Rutas absolutas a los archivos .cs a analizar.
            reference_assemblies: Rutas a ensamblados de referencia adicionales
                (para resolver tipos de NuGet instalados).
            language_version: Versión de C# ("CSharp12", "CSharp11", etc.).
                None = auto-detección.
            include_unresolved: Si True, incluye nodos sin símbolo resuelto.

        Returns:
            Dict con el RoslynExportRoot deserializado del JSON del bridge.
            Estructura: metadata, compilation_unit, semantic_nodes,
                        control_flow, data_flow, symbols

        Raises:
            BridgeNotAvailableError: Bridge no disponible.
            BridgeTimeoutError: Análisis excedió el timeout.
            BridgeAnalysisError: Error HTTP del bridge (400/500).
        """
        if not files:
            raise ValueError("La lista de archivos no puede estar vacía.")

        if len(files) > self._config.max_files_per_request:
            raise ValueError(
                f"Demasiados archivos: {len(files)}. "
                f"Máximo: {self._config.max_files_per_request}."
            )

        # Validar que los archivos existen
        missing = [f for f in files if not Path(f).exists()]
        if missing:
            logger.warning("Archivos no encontrados (el bridge los ignorará): %s", missing[:5])

        payload = {
            "files": files,
            "include_unresolved": (
                include_unresolved
                if include_unresolved is not None
                else self._config.include_unresolved
            ),
        }
        if reference_assemblies:
            payload["reference_assemblies"] = reference_assemblies
        if language_version:
            payload["language_version"] = language_version

        logger.info(
            "Enviando %d archivo(s) al Roslyn Bridge para análisis semántico.",
            len(files),
        )

        return await self._post_with_retry("/analyze", payload)

    async def get_stats(self) -> dict[str, Any]:
        """Obtiene estadísticas del bridge (versión, estado, último análisis)."""
        url = f"{self._config.bridge_url}/analyze/stats"
        async with self._get_session().get(url) as resp:
            resp.raise_for_status()
            return await resp.json()

    # ─────────────────────────────────────────────────────────────────────────
    #  HTTP CON REINTENTOS
    # ─────────────────────────────────────────────────────────────────────────

    async def _post_with_retry(
        self, path: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """POST con reintentos y backoff exponencial para fallos transitorios."""
        url = f"{self._config.bridge_url}{path}"
        last_exc: Exception | None = None

        for attempt in range(1, self._config.max_retries + 1):
            try:
                return await self._post_once(url, payload)

            except BridgeTimeoutError:
                raise  # Los timeouts no se reintentan

            except BridgeAnalysisError as exc:
                if exc.status < 500:
                    raise  # 4xx no se reintentan
                last_exc = exc
                logger.warning(
                    "Bridge retornó %d en intento %d/%d. Reintentando...",
                    exc.status, attempt, self._config.max_retries,
                )

            except (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError) as exc:
                last_exc = exc
                logger.warning(
                    "Error de conexión en intento %d/%d: %s. Reintentando...",
                    attempt, self._config.max_retries, exc,
                )

            if attempt < self._config.max_retries:
                wait = self._config.retry_backoff_seconds * (2 ** (attempt - 1))
                logger.debug("Esperando %.1fs antes del siguiente intento.", wait)
                await asyncio.sleep(wait)

        raise BridgeNotAvailableError(
            f"El bridge no respondió después de {self._config.max_retries} intentos. "
            f"Último error: {last_exc}"
        )

    async def _post_once(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Realiza un único POST y deserializa la respuesta JSON."""
        timeout = aiohttp.ClientTimeout(
            total=self._config.analysis_timeout_seconds + 30,
            connect=10,
        )

        try:
            async with self._get_session().post(
                url,
                json=payload,
                headers={"Accept-Encoding": "gzip", "Content-Type": "application/json"},
                timeout=timeout,
            ) as resp:
                if resp.status == 408:
                    raise BridgeTimeoutError(
                        f"El bridge reportó timeout ({self._config.analysis_timeout_seconds}s). "
                        "Considera aumentar ROSLYN_ANALYSIS_TIMEOUT o analizar menos archivos."
                    )
                if resp.status == 503:
                    raise BridgeAnalysisError(
                        resp.status,
                        "Bridge ocupado (máximo de análisis concurrentes alcanzado). "
                        "Intenta de nuevo en unos segundos.",
                    )
                if resp.status != 200:
                    try:
                        error_body = await resp.json()

                        msg = (
                            error_body.get("details")
                            or error_body.get("error")
                            or f"HTTP {resp.status}"
                        )

                    except Exception:
                        msg = f"HTTP {resp.status}"

                return await self._read_response(resp)

        except asyncio.TimeoutError as exc:
            raise BridgeTimeoutError(
                f"Timeout cliente esperando respuesta del bridge "
                f"({self._config.analysis_timeout_seconds}s)."
            ) from exc

    async def _read_response(self, resp: aiohttp.ClientResponse) -> dict[str, Any]:
        """
        Lee y deserializa la respuesta del bridge.
        El bridge puede comprimir con GZip si el JSON supera 512 KB.
        aiohttp descomprime automáticamente si el servidor incluye
        Content-Encoding: gzip, pero lo manejamos explícitamente
        para mayor compatibilidad.
        """
        content_encoding = resp.headers.get("Content-Encoding", "")
        raw = await resp.read()

        t0 = time.monotonic()

        if content_encoding == "gzip":
            logger.debug(
                "Respuesta GZip recibida: %d KB comprimidos.",
                len(raw) / 1024,
            )
            raw = gzip.decompress(raw)

        logger.debug(
            "Respuesta deserializada: %.1f KB JSON en %.0f ms.",
            len(raw) / 1024,
            (time.monotonic() - t0) * 1000,
        )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BridgeAnalysisError(
                200, f"La respuesta del bridge no es JSON válido: {exc}"
            ) from exc

        self._log_analysis_summary(data)
        return data

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            # Sesión de emergencia para uso fuera del context manager
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self._config.analysis_timeout_seconds + 30
                )
            )
        return self._session

    def _log_analysis_summary(self, data: dict[str, Any]) -> None:
        """Registra un resumen del análisis recibido del bridge."""
        meta = data.get("metadata", {})
        nodes = data.get("semantic_nodes", [])
        classes = data.get("compilation_unit", {}).get("classes", [])
        cfg_methods = data.get("control_flow", {}).get("methods", [])

        logger.info(
            "Análisis Roslyn completado: %d nodos semánticos, %d clases, "
            "%d métodos con CFG. Framework: %s. Errores de compilación: %d.",
            len(nodes),
            len(classes),
            len(cfg_methods),
            meta.get("framework_detected", "generic"),
            len(meta.get("compilation_errors", [])),
        )

        # Advertir sobre errores de compilación (el análisis continúa pero puede ser incompleto)
        errors = meta.get("compilation_errors", [])
        if errors:
            for err in errors[:3]:
                logger.warning(
                    "Error de compilación en %s:%d — %s",
                    err.get("file", "?"),
                    err.get("line", 0),
                    err.get("message", ""),
                )
            if len(errors) > 3:
                logger.warning("... y %d errores más.", len(errors) - 3)


# ─────────────────────────────────────────────────────────────────────────────
#  API SÍNCRONA (wrapper para uso en código no-async)
# ─────────────────────────────────────────────────────────────────────────────

class SyncRoslynClient:
    """
    Wrapper síncrono de RoslynClient para uso en contextos no-async.
    Útil para integración con el CLI scanner.py que puede ser síncrono.

    Uso:
        client = SyncRoslynClient()
        result = client.analyze(["UserController.cs"])
    """

    def __init__(self, config: RoslynClientConfig | None = None) -> None:
        self._config = config or RoslynClientConfig()

    def analyze(
        self,
        files: list[str],
        reference_assemblies: list[str] | None = None,
        language_version: str | None = None,
    ) -> dict[str, Any]:
        """Versión síncrona de RoslynClient.analyze()."""
        return asyncio.run(self._run_async(files, reference_assemblies, language_version))

    def health_check(self) -> dict[str, Any]:
        """Versión síncrona del health check."""
        async def _check():
            async with RoslynClient(self._config) as client:
                return await client.health_check()
        return asyncio.run(_check())

    async def _run_async(
        self,
        files: list[str],
        reference_assemblies: list[str] | None,
        language_version: str | None,
    ) -> dict[str, Any]:
        async with RoslynClient(self._config) as client:
            await client.ensure_bridge_running()
            return await client.analyze(files, reference_assemblies, language_version)
