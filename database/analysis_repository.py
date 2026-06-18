# =============================================================================
#  csharp-sast / database / analysis_repository.py
# =============================================================================
#
#  REPOSITORIO MONGODB PARA RESULTADOS DE ANÁLISIS SAST
#  ───────────────────────────────────────────────────────
#  Persiste y recupera los resultados completos de los análisis SAST
#  ejecutados sobre proyectos C# en la colección MongoDB "analyses".
#
#  RESPONSABILIDADES:
#    1. Guardar el resultado completo de un análisis (scan)
#    2. Recuperar análisis por scan_id, proyecto, archivo o tipo de vuln
#    3. Comparar análisis en el tiempo (trending — ¿mejora o empeora?)
#    4. Estadísticas históricas de seguridad por proyecto
#    5. Gestión del ciclo de vida de los análisis (active, archived)
#    6. Exportar análisis para integración CI/CD (fail/pass por threshold)
#
#  SEPARACIÓN DE RESPONSABILIDADES:
#    • MongoDB              → conexión, pool, TLS
#    • AnalysisRepository   → CRUD de análisis + queries de trending
#    • VulnerabilityClassifier → genera los datos (no los persiste)
#    • html_report / sarif_report → los consumen para el reporte
#
#  COLECCIÓN: analyses
#    _id                   ObjectId (auto)
#    scan_id               str  UUID único por ejecución (GEN por scanner.py)
#    project_name          str  Nombre del proyecto analizado
#    project_path          str  Ruta del proyecto en disco
#    scan_started_at       str  ISO 8601
#    scan_finished_at      str  ISO 8601 (None si está en progreso)
#    scan_duration_sec     float
#    scan_status           str  "running" | "completed" | "failed" | "partial"
#    framework             str  "aspnetcore" | "wcf" | "generic" | etc.
#    language_version      str  "C# 12 / .NET 8"
#    files_analyzed        list[str]  Archivos procesados
#    file_count            int
#    method_count          int
#    node_count            int  Nodos del grafo semántico
#
#    # Resumen de vulnerabilidades
#    summary               dict
#      total_vulns         int
#      critical            int
#      high                int
#      medium              int
#      low                 int
#      info                int
#      false_positives_removed int  (por SemanticAnalyzer/Gemini)
#
#    # Lista de vulnerabilidades (ClassifiedVulnerability serializado)
#    vulnerabilities       list[dict]
#      vuln_id             str  (hash file+line+symbol)
#      vulnerability_kind  str
#      severity            str
#      confidence          str
#      cwe                 str
#      cvss_base           float
#      file                str
#      line                int
#      sink_line           int
#      method_name         str
#      class_name          str
#      framework           str
#      title               str
#      description         str
#      remediation         str
#      source_label        str
#      sink_label          str
#      finding_source      str
#      is_in_loop          bool
#      has_partial_sanitizer bool
#
#    # Métricas del análisis
#    metrics               dict
#      sources_found       int
#      sinks_found         int
#      sanitizers_found    int
#      taint_paths_analyzed int
#      gemini_analyzed     int  (findings enviados a Gemini)
#      gemini_fp_removed   int
#      rules_loaded        int
#
#    # Grafo de taint (referencia, no el grafo completo)
#    graph_stats           dict  (stats del CSharpUnifiedGraph)
#
#    schema_version        str  "1.0"
#    created_at            str  ISO 8601
#    updated_at            str  ISO 8601
#    is_archived           bool
#    tags                  list[str]  etiquetas de usuario (CI/CD, branch, etc.)
#    ci_metadata           dict  (branch, commit, pipeline_id, etc.)
#
# =============================================================================

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Importación defensiva de pymongo
try:
    from pymongo import ASCENDING, DESCENDING
    from pymongo.errors import DuplicateKeyError, PyMongoError
    _PYMONGO_AVAILABLE = True
except ImportError:
    _PYMONGO_AVAILABLE = False
    logger.warning(
        "pymongo no instalado — AnalysisRepository no disponible. "
        "Instalar con: pip install pymongo"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

SCAN_STATUS_RUNNING   = "running"
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_FAILED    = "failed"
SCAN_STATUS_PARTIAL   = "partial"

VALID_SCAN_STATUSES = {
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PARTIAL,
}

DOCUMENT_SCHEMA_VERSION = "1.0"

# Severidades en orden de mayor a menor (para comparaciones)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Umbral de CVSS para CI/CD — análisis "falla" si hay vulns >= este nivel
DEFAULT_CI_FAIL_THRESHOLD = "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SaveAnalysisResult:
    """Resultado de guardar un análisis en MongoDB."""
    success:      bool
    scan_id:      str | None = None
    inserted_id:  str | None = None
    was_updated:  bool = False
    error:        str | None = None

    def __repr__(self) -> str:
        status = "✅" if self.success else "❌"
        action = "UPDATED" if self.was_updated else "INSERTED"
        return f"SaveAnalysisResult({status} {action} scan_id={self.scan_id})"


@dataclass
class VulnTrend:
    """
    Tendencia de vulnerabilidades entre dos análisis del mismo proyecto.
    Muestra qué empeoró, qué mejoró y qué es nuevo.
    """
    scan_id_before:    str
    scan_id_after:     str
    project_name:      str
    date_before:       str
    date_after:        str

    # Cambios en totales
    total_before:      int = 0
    total_after:       int = 0
    total_delta:       int = 0       # Positivo = empeoró, Negativo = mejoró

    # Cambios por severidad
    critical_delta:    int = 0
    high_delta:        int = 0
    medium_delta:      int = 0
    low_delta:         int = 0

    # Vulnerabilidades nuevas (en after pero no en before)
    new_vulns:         list[dict[str, Any]] = field(default_factory=list)
    # Vulnerabilidades resueltas (en before pero no en after)
    resolved_vulns:    list[dict[str, Any]] = field(default_factory=list)
    # Vulnerabilidades persistentes (en ambos)
    persistent_vulns:  list[dict[str, Any]] = field(default_factory=list)

    @property
    def improved(self) -> bool:
        return self.total_delta < 0

    @property
    def worsened(self) -> bool:
        return self.total_delta > 0

    def summary(self) -> str:
        direction = "⬇️ Mejoró" if self.improved else "⬆️ Empeoró" if self.worsened else "→ Sin cambios"
        return (
            f"VulnTrend({direction}: "
            f"{self.total_before} → {self.total_after} vulns, "
            f"Δ={self.total_delta:+d}, "
            f"new={len(self.new_vulns)}, "
            f"resolved={len(self.resolved_vulns)})"
        )


@dataclass
class AnalysisStats:
    """Estadísticas del repositorio de análisis para un proyecto o global."""
    project_name:       str | None = None   # None = estadísticas globales
    total_scans:        int = 0
    completed_scans:    int = 0
    failed_scans:       int = 0
    total_vulns_found:  int = 0
    avg_vulns_per_scan: float = 0.0
    avg_scan_duration:  float = 0.0
    last_scan_at:       str | None = None
    first_scan_at:      str | None = None
    by_severity:        dict[str, int] = field(default_factory=dict)
    by_vulnerability_kind: dict[str, int] = field(default_factory=dict)
    by_framework:       dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        scope = f"project={self.project_name}" if self.project_name else "global"
        return (
            f"AnalysisStats({scope}, "
            f"scans={self.total_scans}, "
            f"vulns_total={self.total_vulns_found}, "
            f"avg_vulns={self.avg_vulns_per_scan:.1f})"
        )


@dataclass
class CiGateResult:
    """
    Resultado de la evaluación de CI/CD gate.
    Determina si el análisis pasa o falla el quality gate de seguridad.
    """
    scan_id:            str
    project_name:       str
    passes_gate:        bool           # True = CI/CD puede continuar
    fail_threshold:     str            # "HIGH", "CRITICAL", etc.
    blocking_vulns:     list[dict]     # Vulns que causan el fallo
    blocking_count:     int
    summary_message:    str

    @property
    def exit_code(self) -> int:
        """0 si pasa, 1 si falla — para uso en scripts CI/CD."""
        return 0 if self.passes_gate else 1


# ─────────────────────────────────────────────────────────────────────────────
#  REPOSITORIO PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisRepository:
    """
    Repositorio MongoDB para resultados de análisis SAST de C#.

    Persiste los análisis generados por el engine y permite consultas
    históricas, comparación de tendencias y evaluación de CI/CD gates.

    Uso:
        from database.mongodb import MongoDB
        from database.analysis_repository import AnalysisRepository

        mongo = MongoDB()
        mongo.connect()
        repo = AnalysisRepository(mongo)

        # Iniciar un análisis
        scan_id = repo.create_scan(project_name="MyApp", project_path="/src")

        # Completar con los resultados del engine
        repo.complete_scan(
            scan_id=scan_id,
            vulnerabilities=classified_vulns,
            metrics=pipeline_metrics,
            files_analyzed=files,
        )

        # Obtener trending entre el último y el anterior scan
        trend = repo.get_trend(project_name="MyApp", last_n=2)

        # Evaluación de CI/CD gate
        gate = repo.evaluate_ci_gate(scan_id, fail_on="HIGH")
        sys.exit(gate.exit_code)
    """

    def __init__(self, mongodb: Any) -> None:
        """
        Args:
            mongodb: Instancia de MongoDB (database/mongodb.py) ya conectada.
        """
        self._mongo = mongodb
        self._collection_name = getattr(
            mongodb, "analysis_collection_name", "analyses"
        )
        self._collection = None

        if mongodb.connected:
            self._collection = mongodb.get_collection(self._collection_name)
            self._ensure_indexes()

    # ─────────────────────────────────────────────────────────────────────────
    #  INICIALIZACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _ensure_indexes(self) -> None:
        """Crea índices MongoDB para queries eficientes."""
        if not self._collection or not _PYMONGO_AVAILABLE:
            return
        try:
            # Índice único por scan_id
            self._collection.create_index(
                [("scan_id", ASCENDING)], unique=True, background=True
            )
            # Índices para queries frecuentes
            self._collection.create_index(
                [("project_name", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("scan_status", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("scan_started_at", DESCENDING)], background=True
            )
            self._collection.create_index(
                [("framework", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("is_archived", ASCENDING)], background=True
            )
            # Índice compuesto para trending (proyecto + fecha)
            self._collection.create_index(
                [("project_name", ASCENDING), ("scan_started_at", DESCENDING)],
                background=True,
            )
            # Índice para queries de vulnerabilidades
            self._collection.create_index(
                [("vulnerabilities.vulnerability_kind", ASCENDING)],
                background=True,
            )
            self._collection.create_index(
                [("vulnerabilities.severity", ASCENDING)],
                background=True,
            )
            self._collection.create_index(
                [("summary.total_vulns", DESCENDING)],
                background=True,
            )
            # Índice compuesto para CI/CD (proyecto + severidad)
            self._collection.create_index(
                [
                    ("project_name", ASCENDING),
                    ("summary.critical", DESCENDING),
                    ("summary.high", DESCENDING),
                ],
                background=True,
            )
            logger.debug(
                "AnalysisRepository: índices asegurados en '%s'",
                self._collection_name,
            )
        except Exception as exc:
            logger.warning(
                "AnalysisRepository: error creando índices: %s", exc
            )

    def _get_collection(self):
        """Retorna la colección, reconectando si es necesario."""
        if not self._mongo.connected:
            raise ConnectionError(
                "MongoDB no conectado. Llamar MongoDB.connect() primero."
            )
        if self._collection is None:
            self._collection = self._mongo.get_collection(self._collection_name)
        return self._collection

    @property
    def is_available(self) -> bool:
        """True si el repositorio está disponible."""
        return _PYMONGO_AVAILABLE and self._mongo.connected

    # ─────────────────────────────────────────────────────────────────────────
    #  ESCRITURA — CICLO DE VIDA DEL ANÁLISIS
    # ─────────────────────────────────────────────────────────────────────────

    def create_scan(
        self,
        project_name:     str,
        project_path:     str = "",
        framework:        str = "generic",
        language_version: str = "C# .NET 8",
        tags:             list[str] | None = None,
        ci_metadata:      dict[str, Any] | None = None,
    ) -> str:
        """
        Crea un nuevo registro de análisis con estado "running".

        Llamar al INICIO del análisis para registrar el scan_id.
        El scan_id se pasa a complete_scan() o fail_scan() al terminar.

        Args:
            project_name:     Nombre del proyecto (para agrupación).
            project_path:     Ruta del proyecto en disco.
            framework:        Framework detectado ("aspnetcore", "wcf", etc.).
            language_version: Versión de C#/.NET.
            tags:             Etiquetas de usuario (branch, environment, etc.).
            ci_metadata:      Metadata de CI/CD (branch, commit_sha, pipeline_id).

        Returns:
            scan_id — UUID único para este análisis.

        Raises:
            ConnectionError si MongoDB no está conectado.
            RuntimeError si el insert falla.
        """
        scan_id = str(uuid.uuid4())
        now     = _now_iso()

        doc: dict[str, Any] = {
            "schema_version":    DOCUMENT_SCHEMA_VERSION,
            "scan_id":           scan_id,
            "project_name":      project_name,
            "project_path":      project_path,
            "scan_started_at":   now,
            "scan_finished_at":  None,
            "scan_duration_sec": None,
            "scan_status":       SCAN_STATUS_RUNNING,
            "framework":         framework,
            "language_version":  language_version,
            "files_analyzed":    [],
            "file_count":        0,
            "method_count":      0,
            "node_count":        0,
            "summary": {
                "total_vulns":            0,
                "critical":               0,
                "high":                   0,
                "medium":                 0,
                "low":                    0,
                "info":                   0,
                "false_positives_removed": 0,
            },
            "vulnerabilities":   [],
            "metrics": {
                "sources_found":       0,
                "sinks_found":         0,
                "sanitizers_found":    0,
                "taint_paths_analyzed": 0,
                "gemini_analyzed":     0,
                "gemini_fp_removed":   0,
                "rules_loaded":        0,
            },
            "graph_stats":  {},
            "error_message": None,
            "is_archived":  False,
            "tags":         tags or [],
            "ci_metadata":  ci_metadata or {},
            "created_at":   now,
            "updated_at":   now,
        }

        try:
            self._get_collection().insert_one(doc)
            logger.info(
                "AnalysisRepository: análisis iniciado — "
                "scan_id=%s, proyecto='%s'",
                scan_id[:8], project_name,
            )
            return scan_id

        except PyMongoError as exc:
            logger.error(
                "AnalysisRepository: error creando análisis: %s", exc
            )
            raise RuntimeError(f"No se pudo crear el análisis en MongoDB: {exc}") from exc

    def complete_scan(
        self,
        scan_id:           str,
        vulnerabilities:   list[Any],     # list[ClassifiedVulnerability]
        metrics:           dict[str, Any] | None = None,
        files_analyzed:    list[str] | None = None,
        method_count:      int = 0,
        node_count:        int = 0,
        graph_stats:       dict[str, Any] | None = None,
        false_positives_removed: int = 0,
    ) -> SaveAnalysisResult:
        """
        Completa un análisis guardando los resultados completos.

        Llamar al FINAL del análisis con los datos del pipeline:
        VulnerabilityClassifier → SemanticAnalyzer → aquí.

        Args:
            scan_id:         scan_id retornado por create_scan().
            vulnerabilities: list[ClassifiedVulnerability] del VulnerabilityClassifier.
            metrics:         Métricas del pipeline (sources, sinks, etc.).
            files_analyzed:  Lista de archivos procesados.
            method_count:    Número de métodos analizados.
            node_count:      Número de nodos del grafo semántico.
            graph_stats:     Estadísticas del CSharpUnifiedGraph.
            false_positives_removed: Número de FPs removidos por Gemini.

        Returns:
            SaveAnalysisResult con el resultado.
        """
        if not self.is_available:
            return SaveAnalysisResult(
                success=False, scan_id=scan_id, error="MongoDB no disponible"
            )

        now     = _now_iso()
        started = self._get_scan_started_at(scan_id)
        duration = _calc_duration_sec(started, now)

        # Serializar vulnerabilidades
        serialized_vulns = [
            self._serialize_vulnerability(v)
            for v in vulnerabilities
        ]

        # Calcular resumen de severidades
        summary = _build_severity_summary(serialized_vulns, false_positives_removed)

        try:
            result = self._get_collection().update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "scan_finished_at":  now,
                        "scan_duration_sec": duration,
                        "scan_status":       SCAN_STATUS_COMPLETED,
                        "files_analyzed":    files_analyzed or [],
                        "file_count":        len(files_analyzed or []),
                        "method_count":      method_count,
                        "node_count":        node_count,
                        "summary":           summary,
                        "vulnerabilities":   serialized_vulns,
                        "metrics":           metrics or {},
                        "graph_stats":       graph_stats or {},
                        "updated_at":        now,
                    }
                },
            )

            success = result.matched_count > 0
            if success:
                logger.info(
                    "AnalysisRepository: análisis completado — "
                    "scan_id=%s | vulns=%d (C=%d, H=%d, M=%d, L=%d) "
                    "| FPs_removed=%d | %.1fs",
                    scan_id[:8],
                    summary["total_vulns"],
                    summary["critical"], summary["high"],
                    summary["medium"],   summary["low"],
                    false_positives_removed,
                    duration or 0.0,
                )
            else:
                logger.warning(
                    "AnalysisRepository: scan_id='%s' no encontrado.",
                    scan_id[:8],
                )

            return SaveAnalysisResult(
                success=success,
                scan_id=scan_id,
                was_updated=success,
                error=None if success else f"scan_id '{scan_id}' no encontrado",
            )

        except PyMongoError as exc:
            logger.error(
                "AnalysisRepository: error completando análisis '%s': %s",
                scan_id[:8], exc,
            )
            return SaveAnalysisResult(success=False, scan_id=scan_id, error=str(exc))

    def fail_scan(
        self,
        scan_id:       str,
        error_message: str,
        partial_vulns: list[Any] | None = None,
    ) -> SaveAnalysisResult:
        """
        Marca un análisis como fallido.

        Llamar cuando el pipeline lanza una excepción no recuperable.

        Args:
            scan_id:       scan_id del análisis fallido.
            error_message: Mensaje de error para diagnóstico.
            partial_vulns: Vulnerabilidades parciales encontradas antes del fallo.

        Returns:
            SaveAnalysisResult.
        """
        if not self.is_available:
            return SaveAnalysisResult(
                success=False, scan_id=scan_id, error="MongoDB no disponible"
            )

        now = _now_iso()
        started = self._get_scan_started_at(scan_id)
        duration = _calc_duration_sec(started, now)

        partial_serialized = []
        partial_summary: dict[str, Any] = {
            "total_vulns": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0,
            "false_positives_removed": 0,
        }

        if partial_vulns:
            partial_serialized = [
                self._serialize_vulnerability(v) for v in partial_vulns
            ]
            partial_summary = _build_severity_summary(partial_serialized, 0)

        status = (
            SCAN_STATUS_PARTIAL if partial_vulns else SCAN_STATUS_FAILED
        )

        try:
            result = self._get_collection().update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "scan_finished_at":  now,
                        "scan_duration_sec": duration,
                        "scan_status":       status,
                        "error_message":     error_message[:500],
                        "vulnerabilities":   partial_serialized,
                        "summary":           partial_summary,
                        "updated_at":        now,
                    }
                },
            )

            success = result.matched_count > 0
            logger.warning(
                "AnalysisRepository: análisis FALLIDO — "
                "scan_id=%s | status=%s | error='%s...'",
                scan_id[:8], status, error_message[:60],
            )
            return SaveAnalysisResult(
                success=success, scan_id=scan_id, was_updated=success
            )

        except PyMongoError as exc:
            logger.error("AnalysisRepository.fail_scan: %s", exc)
            return SaveAnalysisResult(success=False, scan_id=scan_id, error=str(exc))

    def update_progress(
        self,
        scan_id:       str,
        files_done:    int,
        files_total:   int,
        current_file:  str = "",
    ) -> bool:
        """
        Actualiza el progreso de un análisis en curso.

        Útil para mostrar progreso en tiempo real en la CLI.

        Args:
            scan_id:      scan_id del análisis en curso.
            files_done:   Archivos procesados hasta ahora.
            files_total:  Total de archivos a procesar.
            current_file: Archivo procesándose actualmente.

        Returns:
            True si la actualización fue exitosa.
        """
        if not self.is_available:
            return False
        try:
            self._get_collection().update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "progress.files_done":   files_done,
                        "progress.files_total":  files_total,
                        "progress.current_file": current_file,
                        "updated_at":            _now_iso(),
                    }
                },
            )
            return True
        except PyMongoError:
            return False

    # ─────────────────────────────────────────────────────────────────────────
    #  LECTURA — GET
    # ─────────────────────────────────────────────────────────────────────────

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """
        Recupera un análisis completo por su scan_id.

        Returns:
            Document MongoDB completo o None si no existe.
        """
        if not self.is_available:
            return None
        try:
            return self._get_collection().find_one(
                {"scan_id": scan_id}, {"_id": 0}
            )
        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_scan: %s", exc)
            return None

    def get_latest_scan(
        self,
        project_name: str,
        status:       str | None = SCAN_STATUS_COMPLETED,
    ) -> dict[str, Any] | None:
        """
        Recupera el análisis más reciente de un proyecto.

        Args:
            project_name: Nombre del proyecto.
            status:       Filtrar por estado (None = cualquier estado).

        Returns:
            Document del análisis más reciente o None.
        """
        if not self.is_available:
            return None
        try:
            query: dict[str, Any] = {"project_name": project_name}
            if status:
                query["scan_status"] = status

            return self._get_collection().find_one(
                query,
                {"_id": 0},
                sort=[("scan_started_at", DESCENDING)],
            )
        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_latest_scan: %s", exc)
            return None

    def get_scans_by_project(
        self,
        project_name: str,
        limit:        int = 10,
        status:       str | None = None,
        include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Recupera los análisis de un proyecto ordenados por fecha.

        Args:
            project_name:      Nombre del proyecto.
            limit:             Máximo de análisis a retornar.
            status:            Filtrar por estado.
            include_archived:  Si True, incluye análisis archivados.

        Returns:
            Lista de análisis ordenados por fecha descendente.
        """
        if not self.is_available:
            return []
        try:
            query: dict[str, Any] = {"project_name": project_name}
            if status:
                query["scan_status"] = status
            if not include_archived:
                query["is_archived"] = {"$ne": True}

            return list(
                self._get_collection()
                .find(query, {"_id": 0, "vulnerabilities": 0})  # Sin vuln completas
                .sort("scan_started_at", DESCENDING)
                .limit(limit)
            )
        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_scans_by_project: %s", exc)
            return []

    def get_scans_by_vulnerability(
        self,
        vulnerability_kind: str,
        severity:           str | None = None,
        limit:              int = 50,
    ) -> list[dict[str, Any]]:
        """
        Recupera análisis que contienen un tipo de vulnerabilidad específico.

        Útil para identificar proyectos afectados por un tipo de vuln en particular.

        Args:
            vulnerability_kind: "SQL_INJECTION", "XSS", etc.
            severity:           Filtrar adicionalmente por severidad.
            limit:              Máximo de resultados.

        Returns:
            Lista de análisis (solo summary, no lista completa de vulns).
        """
        if not self.is_available:
            return []
        try:
            query: dict[str, Any] = {
                "vulnerabilities.vulnerability_kind": vulnerability_kind,
                "scan_status": SCAN_STATUS_COMPLETED,
            }
            if severity:
                query["vulnerabilities.severity"] = severity

            return list(
                self._get_collection()
                .find(
                    query,
                    {"_id": 0, "vulnerabilities": 0},  # Sin detalle de vulns
                )
                .sort("scan_started_at", DESCENDING)
                .limit(limit)
            )
        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_scans_by_vulnerability: %s", exc)
            return []

    def get_vulnerabilities_from_scan(
        self,
        scan_id:          str,
        severity_filter:  str | None = None,
        vuln_kind_filter: str | None = None,
        limit:            int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recupera la lista de vulnerabilidades de un análisis específico.

        Args:
            scan_id:          ID del análisis.
            severity_filter:  Filtrar por severidad ("CRITICAL", "HIGH", etc.).
            vuln_kind_filter: Filtrar por tipo ("SQL_INJECTION", "XSS", etc.).
            limit:            Máximo de vulnerabilidades a retornar.

        Returns:
            Lista de dicts de vulnerabilidades serializadas.
        """
        if not self.is_available:
            return []
        try:
            doc = self._get_collection().find_one(
                {"scan_id": scan_id},
                {"_id": 0, "vulnerabilities": 1},
            )
            if not doc:
                return []

            vulns: list[dict[str, Any]] = doc.get("vulnerabilities", [])

            # Aplicar filtros
            if severity_filter:
                vulns = [v for v in vulns if v.get("severity") == severity_filter]
            if vuln_kind_filter:
                vulns = [
                    v for v in vulns
                    if v.get("vulnerability_kind") == vuln_kind_filter
                ]
            if limit is not None:
                vulns = vulns[:limit]

            return vulns

        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_vulnerabilities_from_scan: %s", exc)
            return []

    def get_recent_scans(
        self,
        limit:            int = 20,
        status:           str | None = None,
        include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Recupera los análisis más recientes (de todos los proyectos).

        Args:
            limit:             Máximo de resultados.
            status:            Filtrar por estado.
            include_archived:  Si True, incluye archivados.

        Returns:
            Lista de análisis ordenados por fecha descendente.
        """
        if not self.is_available:
            return []
        try:
            query: dict[str, Any] = {}
            if status:
                query["scan_status"] = status
            if not include_archived:
                query["is_archived"] = {"$ne": True}

            return list(
                self._get_collection()
                .find(query, {"_id": 0, "vulnerabilities": 0})
                .sort("scan_started_at", DESCENDING)
                .limit(limit)
            )
        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_recent_scans: %s", exc)
            return []

    def scan_exists(self, scan_id: str) -> bool:
        """True si existe un análisis con ese scan_id."""
        if not self.is_available:
            return False
        try:
            return self._get_collection().count_documents(
                {"scan_id": scan_id}, limit=1
            ) > 0
        except PyMongoError:
            return False

    # ─────────────────────────────────────────────────────────────────────────
    #  TRENDING — COMPARACIÓN ENTRE ANÁLISIS
    # ─────────────────────────────────────────────────────────────────────────

    def get_trend(
        self,
        project_name: str,
        last_n:       int = 2,
    ) -> VulnTrend | None:
        """
        Calcula la tendencia de vulnerabilidades entre los últimos N análisis
        completados de un proyecto.

        Si last_n=2, compara el último análisis con el penúltimo.
        Si last_n=5, compara el último análisis con el de hace 5 análisis.

        Args:
            project_name: Nombre del proyecto.
            last_n:       Número de análisis hacia atrás para comparar.

        Returns:
            VulnTrend con la comparación, o None si no hay suficientes análisis.
        """
        if not self.is_available:
            return None

        try:
            scans = list(
                self._get_collection()
                .find(
                    {
                        "project_name": project_name,
                        "scan_status":  SCAN_STATUS_COMPLETED,
                    },
                    {"_id": 0, "scan_id": 1, "scan_started_at": 1, "summary": 1, "vulnerabilities": 1},
                )
                .sort("scan_started_at", DESCENDING)
                .limit(max(last_n, 2))
            )

            if len(scans) < 2:
                logger.info(
                    "AnalysisRepository: no hay suficientes análisis para "
                    "calcular trending del proyecto '%s' (encontrados: %d).",
                    project_name, len(scans),
                )
                return None

            scan_after  = scans[0]   # El más reciente
            scan_before = scans[-1]  # El más antiguo del rango

            return self._compute_trend(scan_before, scan_after, project_name)

        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_trend: %s", exc)
            return None

    def get_trend_between(
        self,
        scan_id_before: str,
        scan_id_after:  str,
    ) -> VulnTrend | None:
        """
        Calcula la tendencia entre dos análisis específicos por scan_id.

        Args:
            scan_id_before: scan_id del análisis "base".
            scan_id_after:  scan_id del análisis "comparado".

        Returns:
            VulnTrend con la comparación.
        """
        if not self.is_available:
            return None

        scan_before = self.get_scan(scan_id_before)
        scan_after  = self.get_scan(scan_id_after)

        if not scan_before or not scan_after:
            logger.warning(
                "AnalysisRepository.get_trend_between: "
                "uno o ambos scan_ids no encontrados."
            )
            return None

        project_name = scan_after.get("project_name", "unknown")
        return self._compute_trend(scan_before, scan_after, project_name)

    def _compute_trend(
        self,
        scan_before:  dict[str, Any],
        scan_after:   dict[str, Any],
        project_name: str,
    ) -> VulnTrend:
        """Calcula el VulnTrend entre dos análisis."""
        summary_before = scan_before.get("summary", {})
        summary_after  = scan_after.get("summary", {})

        total_before = summary_before.get("total_vulns", 0)
        total_after  = summary_after.get("total_vulns", 0)

        # Calcular deltas por severidad
        def delta(sev: str) -> int:
            return (
                summary_after.get(sev.lower(), 0)
                - summary_before.get(sev.lower(), 0)
            )

        # Identificar vulns nuevas, resueltas y persistentes por vuln_id
        vulns_before = {
            v.get("vuln_id", v.get("vuln_hash", "?")): v
            for v in scan_before.get("vulnerabilities", [])
        }
        vulns_after = {
            v.get("vuln_id", v.get("vuln_hash", "?")): v
            for v in scan_after.get("vulnerabilities", [])
        }

        ids_before = set(vulns_before.keys())
        ids_after  = set(vulns_after.keys())

        new_ids        = ids_after - ids_before
        resolved_ids   = ids_before - ids_after
        persistent_ids = ids_before & ids_after

        # Limit a 20 por categoría para no sobrecargar el resultado
        new_vulns       = [vulns_after[i]  for i in list(new_ids)[:20]]
        resolved_vulns  = [vulns_before[i] for i in list(resolved_ids)[:20]]
        persistent_vulns = [vulns_after[i] for i in list(persistent_ids)[:10]]

        return VulnTrend(
            scan_id_before=scan_before.get("scan_id", "?"),
            scan_id_after=scan_after.get("scan_id", "?"),
            project_name=project_name,
            date_before=scan_before.get("scan_started_at", "?"),
            date_after=scan_after.get("scan_started_at", "?"),
            total_before=total_before,
            total_after=total_after,
            total_delta=total_after - total_before,
            critical_delta=delta("CRITICAL"),
            high_delta=delta("HIGH"),
            medium_delta=delta("MEDIUM"),
            low_delta=delta("LOW"),
            new_vulns=new_vulns,
            resolved_vulns=resolved_vulns,
            persistent_vulns=persistent_vulns,
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  CI/CD GATE
    # ─────────────────────────────────────────────────────────────────────────

    def evaluate_ci_gate(
        self,
        scan_id:        str,
        fail_on:        str = DEFAULT_CI_FAIL_THRESHOLD,
        max_vulns:      int | None = None,
    ) -> CiGateResult:
        """
        Evalúa si un análisis pasa el quality gate de CI/CD.

        El gate falla si hay vulnerabilidades con severidad >= fail_on.
        Puede configurarse en el pipeline CI/CD para bloquear deployments
        cuando se detectan vulnerabilidades críticas.

        Args:
            scan_id:   ID del análisis a evaluar.
            fail_on:   Severidad mínima que causa fallo ("CRITICAL", "HIGH", "MEDIUM").
                       Default: "HIGH" (falla si hay alguna CRITICAL o HIGH).
            max_vulns: Si se especifica, falla si el total de vulns supera este número.

        Returns:
            CiGateResult con passes_gate=True/False y el exit_code para el script.

        Uso en CI/CD:
            gate = repo.evaluate_ci_gate(scan_id, fail_on="HIGH")
            print(gate.summary_message)
            sys.exit(gate.exit_code)  # 0 = pass, 1 = fail
        """
        doc = self.get_scan(scan_id)
        if not doc:
            return CiGateResult(
                scan_id=scan_id,
                project_name="unknown",
                passes_gate=False,
                fail_threshold=fail_on,
                blocking_vulns=[],
                blocking_count=0,
                summary_message=f"❌ scan_id '{scan_id}' no encontrado en MongoDB.",
            )

        project_name = doc.get("project_name", "?")
        summary      = doc.get("summary", {})
        total_vulns  = summary.get("total_vulns", 0)

        # Determinar índice de severidad del threshold
        fail_index = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else 1

        # Obtener vulnerabilidades bloqueantes
        all_vulns = doc.get("vulnerabilities", [])
        blocking_vulns = [
            v for v in all_vulns
            if SEVERITY_ORDER.index(v.get("severity", "INFO"))
            <= fail_index
        ]

        # Verificar máximo de vulns
        max_vulns_exceeded = max_vulns is not None and total_vulns > max_vulns

        passes_gate = (
            len(blocking_vulns) == 0
            and not max_vulns_exceeded
        )

        # Construir mensaje resumen
        if passes_gate:
            msg = (
                f"✅ GATE PASSED — proyecto='{project_name}' | "
                f"scan={scan_id[:8]} | "
                f"total_vulns={total_vulns} | "
                f"ninguna {fail_on}+ encontrada"
            )
        else:
            reasons = []
            if blocking_vulns:
                reasons.append(
                    f"{len(blocking_vulns)} vuln(s) {fail_on}+"
                )
            if max_vulns_exceeded:
                reasons.append(
                    f"total_vulns={total_vulns} > max={max_vulns}"
                )
            msg = (
                f"❌ GATE FAILED — proyecto='{project_name}' | "
                f"scan={scan_id[:8]} | "
                f"razones: {', '.join(reasons)}"
            )

        logger.info("AnalysisRepository CI Gate: %s", msg)

        return CiGateResult(
            scan_id=scan_id,
            project_name=project_name,
            passes_gate=passes_gate,
            fail_threshold=fail_on,
            blocking_vulns=blocking_vulns[:20],  # Max 20 para el output
            blocking_count=len(blocking_vulns),
            summary_message=msg,
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  GESTIÓN DEL CICLO DE VIDA
    # ─────────────────────────────────────────────────────────────────────────

    def archive_scan(self, scan_id: str) -> bool:
        """
        Archiva un análisis (no se muestra en consultas por defecto).

        Args:
            scan_id: ID del análisis a archivar.

        Returns:
            True si se archivó correctamente.
        """
        if not self.is_available:
            return False
        try:
            result = self._get_collection().update_one(
                {"scan_id": scan_id},
                {"$set": {"is_archived": True, "updated_at": _now_iso()}},
            )
            archived = result.matched_count > 0
            if archived:
                logger.info(
                    "AnalysisRepository: análisis '%s' archivado.", scan_id[:8]
                )
            return archived
        except PyMongoError as exc:
            logger.error("AnalysisRepository.archive_scan: %s", exc)
            return False

    def add_tags(self, scan_id: str, tags: list[str]) -> bool:
        """Añade tags a un análisis (p.ej. 'ci-cd', 'pre-release', branch name)."""
        if not self.is_available:
            return False
        try:
            result = self._get_collection().update_one(
                {"scan_id": scan_id},
                {
                    "$addToSet": {"tags": {"$each": tags}},
                    "$set": {"updated_at": _now_iso()},
                },
            )
            return result.matched_count > 0
        except PyMongoError as exc:
            logger.error("AnalysisRepository.add_tags: %s", exc)
            return False

    def delete_scan(self, scan_id: str) -> bool:
        """
        Elimina un análisis permanentemente.

        Args:
            scan_id: ID del análisis a eliminar.

        Returns:
            True si se eliminó correctamente.
        """
        if not self.is_available:
            return False
        try:
            result = self._get_collection().delete_one({"scan_id": scan_id})
            deleted = result.deleted_count > 0
            if deleted:
                logger.info(
                    "AnalysisRepository: análisis '%s' eliminado.", scan_id[:8]
                )
            return deleted
        except PyMongoError as exc:
            logger.error("AnalysisRepository.delete_scan: %s", exc)
            return False

    def delete_old_scans(
        self,
        project_name:    str,
        keep_last_n:     int = 10,
    ) -> int:
        """
        Elimina análisis antiguos de un proyecto, manteniendo solo los últimos N.

        Útil para limpiar el repositorio y liberar espacio en MongoDB.

        Args:
            project_name: Nombre del proyecto.
            keep_last_n:  Cuántos análisis mantener (default: 10).

        Returns:
            Número de análisis eliminados.
        """
        if not self.is_available:
            return 0

        try:
            # Obtener todos los scan_ids del proyecto, ordenados por fecha
            all_scans = list(
                self._get_collection()
                .find(
                    {"project_name": project_name},
                    {"scan_id": 1, "scan_started_at": 1},
                )
                .sort("scan_started_at", DESCENDING)
            )

            if len(all_scans) <= keep_last_n:
                return 0

            # Los scan_ids a eliminar son los más antiguos
            to_delete = [s["scan_id"] for s in all_scans[keep_last_n:]]

            result = self._get_collection().delete_many(
                {"scan_id": {"$in": to_delete}}
            )
            count = result.deleted_count

            if count:
                logger.info(
                    "AnalysisRepository: %d análisis antiguos eliminados "
                    "del proyecto '%s' (manteniendo %d más recientes).",
                    count, project_name, keep_last_n,
                )
            return count

        except PyMongoError as exc:
            logger.error("AnalysisRepository.delete_old_scans: %s", exc)
            return 0

    # ─────────────────────────────────────────────────────────────────────────
    #  ESTADÍSTICAS
    # ─────────────────────────────────────────────────────────────────────────

    def get_stats(
        self,
        project_name: str | None = None,
    ) -> AnalysisStats:
        """
        Calcula estadísticas del repositorio de análisis.

        Args:
            project_name: Si se especifica, estadísticas solo de ese proyecto.
                          Si None, estadísticas globales de todos los proyectos.

        Returns:
            AnalysisStats con métricas completas.
        """
        if not self.is_available:
            return AnalysisStats(project_name=project_name)

        try:
            collection = self._get_collection()
            base_query: dict[str, Any] = {}
            if project_name:
                base_query["project_name"] = project_name

            stats = AnalysisStats(project_name=project_name)

            # Totales básicos
            stats.total_scans = collection.count_documents(base_query)
            stats.completed_scans = collection.count_documents(
                {**base_query, "scan_status": SCAN_STATUS_COMPLETED}
            )
            stats.failed_scans = collection.count_documents(
                {**base_query, "scan_status": SCAN_STATUS_FAILED}
            )

            if stats.total_scans == 0:
                return stats

            # Promedio de vulnerabilidades por scan
            pipeline_avg = [
                {"$match": {**base_query, "scan_status": SCAN_STATUS_COMPLETED}},
                {"$group": {
                    "_id": None,
                    "avg_vulns":     {"$avg": "$summary.total_vulns"},
                    "total_vulns":   {"$sum": "$summary.total_vulns"},
                    "avg_duration":  {"$avg": "$scan_duration_sec"},
                    "last_scan":     {"$max": "$scan_started_at"},
                    "first_scan":    {"$min": "$scan_started_at"},
                }},
            ]
            for doc in collection.aggregate(pipeline_avg):
                stats.avg_vulns_per_scan = round(doc.get("avg_vulns") or 0.0, 1)
                stats.total_vulns_found  = int(doc.get("total_vulns") or 0)
                stats.avg_scan_duration  = round(doc.get("avg_duration") or 0.0, 1)
                stats.last_scan_at       = doc.get("last_scan")
                stats.first_scan_at      = doc.get("first_scan")

            # Distribución por severidad (suma acumulada)
            pipeline_sev = [
                {"$match": {**base_query, "scan_status": SCAN_STATUS_COMPLETED}},
                {"$group": {
                    "_id":      None,
                    "critical": {"$sum": "$summary.critical"},
                    "high":     {"$sum": "$summary.high"},
                    "medium":   {"$sum": "$summary.medium"},
                    "low":      {"$sum": "$summary.low"},
                    "info":     {"$sum": "$summary.info"},
                }},
            ]
            for doc in collection.aggregate(pipeline_sev):
                stats.by_severity = {
                    "CRITICAL": doc.get("critical", 0),
                    "HIGH":     doc.get("high", 0),
                    "MEDIUM":   doc.get("medium", 0),
                    "LOW":      doc.get("low", 0),
                    "INFO":     doc.get("info", 0),
                }

            # Distribución por tipo de vulnerabilidad
            pipeline_kind = [
                {"$match": {**base_query, "scan_status": SCAN_STATUS_COMPLETED}},
                {"$unwind": "$vulnerabilities"},
                {"$group": {
                    "_id":   "$vulnerabilities.vulnerability_kind",
                    "count": {"$sum": 1},
                }},
                {"$sort": {"count": DESCENDING}},
                {"$limit": 15},
            ]
            for doc in collection.aggregate(pipeline_kind):
                if doc["_id"]:
                    stats.by_vulnerability_kind[doc["_id"]] = doc["count"]

            # Distribución por framework
            pipeline_fw = [
                {"$match": base_query},
                {"$group": {"_id": "$framework", "count": {"$sum": 1}}},
                {"$sort": {"count": DESCENDING}},
            ]
            for doc in collection.aggregate(pipeline_fw):
                if doc["_id"]:
                    stats.by_framework[doc["_id"]] = doc["count"]

            return stats

        except PyMongoError as exc:
            logger.error("AnalysisRepository.get_stats: %s", exc)
            return AnalysisStats(project_name=project_name)

    def get_stats_dict(
        self,
        project_name: str | None = None,
    ) -> dict[str, Any]:
        """Versión dict de get_stats() para serialización."""
        stats = self.get_stats(project_name)
        return {
            "project_name":        stats.project_name,
            "total_scans":         stats.total_scans,
            "completed_scans":     stats.completed_scans,
            "failed_scans":        stats.failed_scans,
            "total_vulns_found":   stats.total_vulns_found,
            "avg_vulns_per_scan":  stats.avg_vulns_per_scan,
            "avg_scan_duration":   stats.avg_scan_duration,
            "last_scan_at":        stats.last_scan_at,
            "first_scan_at":       stats.first_scan_at,
            "by_severity":         stats.by_severity,
            "by_vulnerability_kind": stats.by_vulnerability_kind,
            "by_framework":        stats.by_framework,
            "summary":             stats.summary(),
        }

    def count_projects(self) -> int:
        """Retorna el número de proyectos únicos con análisis."""
        if not self.is_available:
            return 0
        try:
            return len(
                self._get_collection().distinct("project_name", {})
            )
        except PyMongoError:
            return 0

    def list_projects(self) -> list[str]:
        """Retorna la lista de proyectos únicos con análisis."""
        if not self.is_available:
            return []
        try:
            return sorted(
                self._get_collection().distinct("project_name", {})
            )
        except PyMongoError:
            return []

    # ─────────────────────────────────────────────────────────────────────────
    #  SERIALIZACIÓN DE VULNERABILIDADES
    # ─────────────────────────────────────────────────────────────────────────

    def _serialize_vulnerability(self, vuln: Any) -> dict[str, Any]:
        """
        Serializa una ClassifiedVulnerability al formato del documento MongoDB.

        Diseñado para ser compatible con los campos de ClassifiedVulnerability
        de vulnerability_classifier.py — accede con getattr para no crear
        un import circular.

        Args:
            vuln: ClassifiedVulnerability instance.

        Returns:
            Dict serializable para insertar en MongoDB.
        """
        def _get(attr: str, default: Any = None) -> Any:
            return getattr(vuln, attr, default)

        def _enum_value(attr: str, default: str = "") -> str:
            val = getattr(vuln, attr, None)
            if val is None:
                return default
            return val.value if hasattr(val, "value") else str(val)

        # Generar un hash estable para el vuln_id si no existe
        vuln_id = _get("vuln_id")
        if not vuln_id:
            key = f"{_get('file', '')}:{_get('sink_line', 0)}:{_get('cwe', '')}"
            vuln_id = hashlib.sha256(key.encode()).hexdigest()[:16]

        # Serializar CVSS vector si existe
        cvss = _get("cvss")
        cvss_dict: dict[str, Any] = {}
        if cvss:
            cvss_dict = {
                "base_score":    getattr(cvss, "base_score", 0.0),
                "vector_string": getattr(cvss, "vector_string", ""),
            }

        return {
            "vuln_id":             vuln_id,
            "vulnerability_kind":  _enum_value("vulnerability_kind"),
            "severity":            _enum_value("severity"),
            "confidence":          _enum_value("confidence"),
            "finding_source":      _enum_value("finding_source"),
            "cwe":                 _get("cwe", ""),
            "cwe_name":            _get("cwe_name", ""),
            "cvss":                cvss_dict,
            "cvss_base":           cvss_dict.get("base_score", 0.0),
            "file":                _get("file", ""),
            "line":                _get("line", 0),
            "sink_line":           _get("sink_line", 0),
            "code_snippet":        _get("code_snippet", "")[:200],
            "method_name":         _get("method_name", ""),
            "class_name":          _get("class_name", ""),
            "framework":           _get("framework", ""),
            "title":               _get("title", ""),
            "description":         _get("description", "")[:500],
            "remediation":         _get("remediation", "")[:500],
            "references":          _get("references", []),
            "source_label":        _get("source_label", ""),
            "sink_label":          _get("sink_label", ""),
            "taint_path_summary":  _get("taint_path_summary", [])[:10],
            "is_in_loop":          _get("is_in_loop", False),
            "has_partial_sanitizer": _get("has_partial_sanitizer", False),
            "is_entry_point":      _get("is_entry_point", False),
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS INTERNOS
    # ─────────────────────────────────────────────────────────────────────────

    def _get_scan_started_at(self, scan_id: str) -> str | None:
        """Recupera el timestamp de inicio de un análisis."""
        if not self.is_available:
            return None
        try:
            doc = self._get_collection().find_one(
                {"scan_id": scan_id},
                {"scan_started_at": 1},
            )
            return doc.get("scan_started_at") if doc else None
        except PyMongoError:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    #  UTILIDADES
    # ─────────────────────────────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Estado del repositorio."""
        return {
            "available":         self.is_available,
            "collection":        self._collection_name,
            "mongodb_connected": self._mongo.connected,
            "pymongo_installed": _PYMONGO_AVAILABLE,
            "total_scans":       self.count_scans() if self.is_available else 0,
            "projects":          self.count_projects() if self.is_available else 0,
        }

    def count_scans(self, query: dict[str, Any] | None = None) -> int:
        """Cuenta análisis con un filtro opcional."""
        if not self.is_available:
            return 0
        try:
            return self._get_collection().count_documents(query or {})
        except PyMongoError:
            return 0

    def healthcheck(self) -> bool:
        """Verifica que el repositorio puede hacer operaciones básicas."""
        if not self.is_available:
            return False
        try:
            self._get_collection().count_documents({}, limit=1)
            return True
        except PyMongoError:
            return False

    def __repr__(self) -> str:
        status = "AVAILABLE" if self.is_available else "UNAVAILABLE"
        return (
            f"AnalysisRepository({status}, "
            f"collection={self._collection_name}, "
            f"scans={self.count_scans()}, "
            f"projects={self.count_projects()})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS DE MÓDULO
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    """Retorna el timestamp actual en formato ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


def _calc_duration_sec(
    started_at: str | None,
    finished_at: str,
) -> float | None:
    """Calcula la duración en segundos entre dos timestamps ISO 8601."""
    if not started_at:
        return None
    try:
        start = datetime.fromisoformat(started_at)
        end   = datetime.fromisoformat(finished_at)
        return round((end - start).total_seconds(), 2)
    except (ValueError, TypeError):
        return None


def _build_severity_summary(
    vulnerabilities:         list[dict[str, Any]],
    false_positives_removed: int,
) -> dict[str, Any]:
    """
    Calcula el resumen de severidades desde la lista de vulnerabilidades.

    Args:
        vulnerabilities:         Lista de vulns serializadas.
        false_positives_removed: FPs removidos por Gemini (para el resumen).

    Returns:
        Dict con total_vulns y conteo por severidad.
    """
    summary: dict[str, Any] = {
        "total_vulns":             0,
        "critical":                0,
        "high":                    0,
        "medium":                  0,
        "low":                     0,
        "info":                    0,
        "false_positives_removed": false_positives_removed,
    }

    for v in vulnerabilities:
        sev = v.get("severity", "INFO").upper()
        summary["total_vulns"] += 1
        if sev == "CRITICAL":
            summary["critical"] += 1
        elif sev == "HIGH":
            summary["high"] += 1
        elif sev == "MEDIUM":
            summary["medium"] += 1
        elif sev == "LOW":
            summary["low"] += 1
        else:
            summary["info"] += 1

    return summary