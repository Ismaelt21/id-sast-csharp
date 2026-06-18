# =============================================================================
#  csharp-sast / database / rule_repository.py
# =============================================================================
#
#  REPOSITORIO DE REGLAS SAST GENERADAS POR IA
#  ─────────────────────────────────────────────
#  Persiste y recupera las reglas SAST generadas por RuleGenerator
#  en la colección MongoDB "security_rules".
#
#  RESPONSABILIDADES:
#    1. Guardar reglas generadas (GeneratedRule → documento MongoDB)
#    2. Ciclo de revisión: pending → approved / rejected
#    3. Recuperar reglas por ID, tipo, vulnerabilidad, framework
#    4. Exportar reglas aprobadas para cargarlas en RuleLoader
#    5. Detectar colisiones: symbols ya almacenados en la BD
#    6. Estadísticas del catálogo generado
#
#  SEPARACIÓN DE RESPONSABILIDADES:
#    • MongoDB   → conexión, pool, TLS
#    • RuleRepository → CRUD de reglas + lógica de revisión
#    • RuleGenerator  → genera las reglas (no las persiste directamente)
#    • RuleLoader     → carga reglas en el engine (built-in + custom)
#
#  CICLO DE VIDA DE UNA REGLA:
#    RuleGenerator.generate_from_pattern()
#      → GeneratedRule (en memoria)
#      → RuleRepository.save_rule()
#      → MongoDB doc con review_status="pending"
#      → Revisión humana: mark_reviewed(approved=True)
#      → RuleRepository.export_for_rule_loader()
#      → RuleLoader(custom_path=...) los carga en el engine
#
#  COLECCIÓN: security_rules
#    _id               ObjectId (auto)
#    rule_id           str   GEN-SQL-001 (único)
#    rule_type         str   sink | source | sanitizer
#    symbol            str   Roslyn FQN
#    vulnerability     str   SQL_INJECTION (solo sinks)
#    rule_data         dict  La regla completa
#    generated_at      str   ISO 8601
#    gemini_model      str   gemini-1.5-pro
#    pattern_source    str   pattern_description | code_analysis | manual
#    confidence_ai     float 0.0-1.0
#    is_valid          bool
#    is_production_ready bool
#    collisions        list[str]
#    review_status     str   pending | approved | rejected
#    reviewed_by       str | None
#    reviewed_at       str | None
#    review_notes      str | None
#    frameworks        list[str]
#    tags              list[str]
#    version           int
#    created_at        str   ISO 8601
#    updated_at        str   ISO 8601
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Importación defensiva de pymongo
try:
    from pymongo import ASCENDING, DESCENDING, TEXT
    from pymongo.errors import DuplicateKeyError, PyMongoError
    _PYMONGO_AVAILABLE = True
except ImportError:
    _PYMONGO_AVAILABLE = False
    logger.warning(
        "pymongo no instalado — RuleRepository no disponible. "
        "Instalar con: pip install pymongo"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

REVIEW_STATUS_PENDING  = "pending"
REVIEW_STATUS_APPROVED = "approved"
REVIEW_STATUS_REJECTED = "rejected"

VALID_REVIEW_STATUSES = {
    REVIEW_STATUS_PENDING,
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_REJECTED,
}

# Versión del schema de documentos
DOCUMENT_SCHEMA_VERSION = "1.0"


# ─────────────────────────────────────────────────────────────────────────────
#  MODELOS DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SaveResult:
    """Resultado de una operación de guardado."""
    success:     bool
    rule_id:     str | None = None
    inserted_id: str | None = None
    was_updated: bool = False     # True si actualizó una regla existente
    error:       str | None = None

    def __repr__(self) -> str:
        status = "✅" if self.success else "❌"
        action = "UPDATED" if self.was_updated else "INSERTED"
        return (
            f"SaveResult({status} {action} "
            f"rule_id={self.rule_id}, "
            f"error={self.error})"
        )


@dataclass
class ReviewResult:
    """Resultado de una operación de revisión."""
    success:      bool
    rule_id:      str
    new_status:   str | None = None
    error:        str | None = None


@dataclass
class RuleStats:
    """Estadísticas del repositorio de reglas."""
    total:             int = 0
    pending_review:    int = 0
    approved:          int = 0
    rejected:          int = 0
    production_ready:  int = 0
    by_type:           dict[str, int] = field(default_factory=dict)
    by_vulnerability:  dict[str, int] = field(default_factory=dict)
    by_framework:      dict[str, int] = field(default_factory=dict)
    avg_confidence_ai: float = 0.0

    def summary(self) -> str:
        return (
            f"RuleStats(total={self.total}, "
            f"pending={self.pending_review}, "
            f"approved={self.approved}, "
            f"rejected={self.rejected}, "
            f"ready={self.production_ready})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  REPOSITORIO PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class RuleRepository:
    """
    Repositorio MongoDB para reglas SAST generadas por IA.

    Uso:
        from database.mongodb import MongoDB
        from database.rule_repository import RuleRepository

        mongo = MongoDB()
        mongo.connect()

        repo = RuleRepository(mongo)

        # Guardar una regla generada por RuleGenerator
        result = repo.save_rule(generated_rule)

        # Aprobar después de revisión humana
        repo.mark_reviewed(
            rule_id="GEN-SQL-001",
            approved=True,
            reviewer="security-team",
            notes="Verificado con Roslyn — símbolo correcto"
        )

        # Exportar para usar en RuleLoader
        rules = repo.export_for_rule_loader()
        # → loader = RuleLoader(custom_path=...) con estas reglas
    """

    def __init__(self, mongodb: Any) -> None:
        """
        Args:
            mongodb: Instancia de MongoDB (database/mongodb.py) ya conectada.
        """
        self._mongo = mongodb
        self._collection_name = getattr(
            mongodb, "rules_collection_name", "security_rules"
        )
        self._collection = None

        if mongodb.connected:
            self._collection = mongodb.get_collection(self._collection_name)
            self._ensure_indexes()

    # ─────────────────────────────────────────────────────────────────────────
    #  INICIALIZACIÓN Y CONEXIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _ensure_indexes(self) -> None:
        """Crea los índices necesarios si no existen."""
        if not self._collection or not _PYMONGO_AVAILABLE:
            return
        try:
            self._collection.create_index(
                [("rule_id", ASCENDING)], unique=True, background=True
            )
            self._collection.create_index(
                [("rule_type", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("vulnerability", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("review_status", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("is_production_ready", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("frameworks", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("symbol", ASCENDING)], background=True
            )
            self._collection.create_index(
                [("confidence_ai", DESCENDING)], background=True
            )
            self._collection.create_index(
                [("created_at", DESCENDING)], background=True
            )
            # Índice de texto para búsqueda en descripción y nombre
            self._collection.create_index(
                [("rule_data.name", TEXT), ("rule_data.description", TEXT)],
                background=True,
            )
            logger.debug(
                "RuleRepository: índices asegurados en '%s'",
                self._collection_name,
            )
        except Exception as exc:
            logger.warning("RuleRepository: error creando índices: %s", exc)

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
        """True si el repositorio está disponible y MongoDB conectado."""
        return _PYMONGO_AVAILABLE and self._mongo.connected

    # ─────────────────────────────────────────────────────────────────────────
    #  ESCRITURA — SAVE
    # ─────────────────────────────────────────────────────────────────────────

    def save_rule(self, generated_rule: Any) -> SaveResult:
        """
        Guarda una regla generada por RuleGenerator en MongoDB.

        Si la regla ya existe (mismo rule_id) → actualiza la versión.
        Si es nueva → inserta con review_status="pending".

        Args:
            generated_rule: GeneratedRule de core/ai/rule_generator.py.

        Returns:
            SaveResult con el resultado de la operación.
        """
        if not self.is_available:
            return SaveResult(
                success=False,
                error="MongoDB no disponible",
            )

        try:
            doc = self._generated_rule_to_document(generated_rule)
            collection = self._get_collection()

            # Intentar insertar — si duplica, actualizar
            try:
                result = collection.insert_one(doc)
                return SaveResult(
                    success=True,
                    rule_id=doc["rule_id"],
                    inserted_id=str(result.inserted_id),
                    was_updated=False,
                )

            except DuplicateKeyError:
                # Regla ya existe → actualizar con nueva versión
                update_result = collection.update_one(
                    {"rule_id": doc["rule_id"]},
                    {
                        "$set": {
                            "rule_data":          doc["rule_data"],
                            "confidence_ai":      doc["confidence_ai"],
                            "is_valid":           doc["is_valid"],
                            "is_production_ready": doc["is_production_ready"],
                            "collisions":         doc["collisions"],
                            "updated_at":         _now_iso(),
                        },
                        "$inc": {"version": 1},
                    },
                )
                updated = update_result.modified_count > 0
                logger.info(
                    "RuleRepository: regla '%s' %s en MongoDB.",
                    doc["rule_id"],
                    "actualizada" if updated else "sin cambios",
                )
                return SaveResult(
                    success=True,
                    rule_id=doc["rule_id"],
                    was_updated=updated,
                )

        except PyMongoError as exc:
            logger.error("RuleRepository: error guardando regla: %s", exc)
            return SaveResult(
                success=False,
                rule_id=getattr(generated_rule, "rule_id", None),
                error=str(exc),
            )

    def save_rules(self, generated_rules: list[Any]) -> list[SaveResult]:
        """
        Guarda múltiples reglas generadas.

        Args:
            generated_rules: Lista de GeneratedRule.

        Returns:
            Lista de SaveResult en el mismo orden.
        """
        results: list[SaveResult] = []
        for gr in generated_rules:
            result = self.save_rule(gr)
            results.append(result)

        success_count = sum(1 for r in results if r.success)
        logger.info(
            "RuleRepository: %d/%d reglas guardadas exitosamente.",
            success_count, len(generated_rules),
        )
        return results

    def save_rule_dict(
        self,
        rule_dict:      dict[str, Any],
        pattern_source: str = "manual",
        confidence_ai:  float = 0.0,
    ) -> SaveResult:
        """
        Guarda una regla a partir de un dict directo (sin GeneratedRule).
        Útil para añadir reglas manualmente sin pasar por Gemini.

        Args:
            rule_dict:      Dict con la regla en formato del engine.
            pattern_source: Origen de la regla ("manual", "pattern_description", etc.)
            confidence_ai:  Confianza AI (0.0 para reglas manuales).

        Returns:
            SaveResult.
        """
        if not self.is_available:
            return SaveResult(success=False, error="MongoDB no disponible")

        now = _now_iso()
        rule_id = rule_dict.get("id", "MANUAL-?")

        doc: dict[str, Any] = {
            "schema_version":    DOCUMENT_SCHEMA_VERSION,
            "rule_id":           rule_id,
            "rule_type":         rule_dict.get("rule_type", ""),
            "symbol":            rule_dict.get("symbol", ""),
            "vulnerability":     rule_dict.get("vulnerability", ""),
            "rule_data":         rule_dict,
            "generated_at":      now,
            "gemini_model":      "manual",
            "pattern_source":    pattern_source,
            "confidence_ai":     confidence_ai,
            "is_valid":          True,
            "is_production_ready": True,
            "collisions":        [],
            "review_status":     REVIEW_STATUS_PENDING,
            "reviewed_by":       None,
            "reviewed_at":       None,
            "review_notes":      None,
            "frameworks":        rule_dict.get("frameworks", []),
            "tags":              rule_dict.get("tags", []),
            "version":           1,
            "created_at":        now,
            "updated_at":        now,
        }

        try:
            collection = self._get_collection()
            try:
                result = collection.insert_one(doc)
                return SaveResult(
                    success=True,
                    rule_id=rule_id,
                    inserted_id=str(result.inserted_id),
                )
            except DuplicateKeyError:
                return SaveResult(
                    success=False,
                    rule_id=rule_id,
                    error=f"Regla '{rule_id}' ya existe. Usar save_rule() para actualizar.",
                )
        except PyMongoError as exc:
            return SaveResult(success=False, error=str(exc))

    # ─────────────────────────────────────────────────────────────────────────
    #  LECTURA — GET
    # ─────────────────────────────────────────────────────────────────────────

    def get_rule_by_id(self, rule_id: str) -> dict[str, Any] | None:
        """
        Recupera una regla por su rule_id (GEN-SQL-001).

        Returns:
            Dict con la regla completa (document MongoDB) o None si no existe.
        """
        if not self.is_available:
            return None
        try:
            doc = self._get_collection().find_one(
                {"rule_id": rule_id},
                {"_id": 0},
            )
            return doc
        except PyMongoError as exc:
            logger.error("RuleRepository.get_rule_by_id: %s", exc)
            return None

    def get_rules_by_vulnerability(
        self,
        vulnerability: str,
        status:        str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recupera reglas por tipo de vulnerabilidad.

        Args:
            vulnerability: Tipo de vuln: "SQL_INJECTION", "XSS", etc.
            status:        Filtrar por review_status (None = todos).

        Returns:
            Lista de documents de reglas.
        """
        if not self.is_available:
            return []
        try:
            query: dict[str, Any] = {"vulnerability": vulnerability}
            if status:
                query["review_status"] = status
            return list(
                self._get_collection()
                .find(query, {"_id": 0})
                .sort("confidence_ai", DESCENDING)
            )
        except PyMongoError as exc:
            logger.error("RuleRepository.get_rules_by_vulnerability: %s", exc)
            return []

    def get_rules_by_type(
        self,
        rule_type: str,
        status:    str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recupera reglas por tipo: "sink", "source" o "sanitizer".

        Args:
            rule_type: "sink" | "source" | "sanitizer"
            status:    Filtrar por review_status (None = todos).
        """
        if not self.is_available:
            return []
        try:
            query: dict[str, Any] = {"rule_type": rule_type}
            if status:
                query["review_status"] = status
            return list(
                self._get_collection()
                .find(query, {"_id": 0})
                .sort("created_at", DESCENDING)
            )
        except PyMongoError as exc:
            logger.error("RuleRepository.get_rules_by_type: %s", exc)
            return []

    def get_rules_by_framework(
        self,
        framework: str,
        status:    str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recupera reglas que aplican a un framework específico.

        Args:
            framework: "aspnetcore", "wcf", "generic", etc.
            status:    Filtrar por review_status.
        """
        if not self.is_available:
            return []
        try:
            query: dict[str, Any] = {"frameworks": framework}
            if status:
                query["review_status"] = status
            return list(
                self._get_collection()
                .find(query, {"_id": 0})
                .sort("confidence_ai", DESCENDING)
            )
        except PyMongoError as exc:
            logger.error("RuleRepository.get_rules_by_framework: %s", exc)
            return []

    def get_production_ready_rules(self) -> list[dict[str, Any]]:
        """
        Recupera todas las reglas aprobadas y listas para producción.
        Estas son las reglas que se cargan en RuleLoader como custom rules.

        Returns:
            Lista de documents de reglas aprobadas y válidas.
        """
        if not self.is_available:
            return []
        try:
            return list(
                self._get_collection()
                .find(
                    {
                        "is_production_ready": True,
                        "review_status":       REVIEW_STATUS_APPROVED,
                    },
                    {"_id": 0},
                )
                .sort("confidence_ai", DESCENDING)
            )
        except PyMongoError as exc:
            logger.error("RuleRepository.get_production_ready_rules: %s", exc)
            return []

    def get_rules_pending_review(self) -> list[dict[str, Any]]:
        """
        Recupera reglas que esperan revisión humana.

        Returns:
            Lista de reglas con review_status="pending", ordenadas
            por confidence_ai descendente (las más confiables primero).
        """
        if not self.is_available:
            return []
        try:
            return list(
                self._get_collection()
                .find(
                    {"review_status": REVIEW_STATUS_PENDING},
                    {"_id": 0},
                )
                .sort("confidence_ai", DESCENDING)
            )
        except PyMongoError as exc:
            logger.error("RuleRepository.get_rules_pending_review: %s", exc)
            return []

    def get_recent_rules(self, limit: int = 20) -> list[dict[str, Any]]:
        """Recupera las reglas más recientes."""
        if not self.is_available:
            return []
        try:
            return list(
                self._get_collection()
                .find({}, {"_id": 0})
                .sort("created_at", DESCENDING)
                .limit(limit)
            )
        except PyMongoError as exc:
            logger.error("RuleRepository.get_recent_rules: %s", exc)
            return []

    def get_all_symbols(self) -> set[str]:
        """
        Retorna el conjunto de todos los símbolos almacenados.
        Usado por RuleGenerator para detectar colisiones antes de generar.

        Returns:
            Set de strings con los símbolos (Roslyn FQN) de todas las reglas.
        """
        if not self.is_available:
            return set()
        try:
            symbols = self._get_collection().distinct("symbol", {})
            return set(s for s in symbols if s)
        except PyMongoError as exc:
            logger.error("RuleRepository.get_all_symbols: %s", exc)
            return set()

    def get_all_rule_ids(self) -> set[str]:
        """
        Retorna el conjunto de todos los rule_ids almacenados.
        Usado por RuleGenerator para evitar IDs duplicados.
        """
        if not self.is_available:
            return set()
        try:
            ids = self._get_collection().distinct("rule_id", {})
            return set(i for i in ids if i)
        except PyMongoError as exc:
            logger.error("RuleRepository.get_all_rule_ids: %s", exc)
            return set()

    def search_rules(
        self,
        query_text:  str,
        limit:       int = 20,
    ) -> list[dict[str, Any]]:
        """
        Búsqueda de texto en nombre y descripción de las reglas.

        Args:
            query_text: Texto a buscar (usa índice TEXT de MongoDB).
            limit:      Máximo de resultados.

        Returns:
            Lista de reglas que coinciden, ordenadas por relevancia.
        """
        if not self.is_available:
            return []
        try:
            return list(
                self._get_collection()
                .find(
                    {"$text": {"$search": query_text}},
                    {"_id": 0, "score": {"$meta": "textScore"}},
                )
                .sort([("score", {"$meta": "textScore"})])
                .limit(limit)
            )
        except PyMongoError as exc:
            logger.warning("RuleRepository.search_rules: %s", exc)
            # Fallback: búsqueda por regex si el índice TEXT no está disponible
            try:
                import re
                pattern = re.compile(query_text, re.IGNORECASE)
                return list(
                    self._get_collection()
                    .find(
                        {
                            "$or": [
                                {"rule_data.name": {"$regex": pattern}},
                                {"rule_data.description": {"$regex": pattern}},
                                {"symbol": {"$regex": pattern}},
                            ]
                        },
                        {"_id": 0},
                    )
                    .limit(limit)
                )
            except PyMongoError:
                return []

    # ─────────────────────────────────────────────────────────────────────────
    #  CICLO DE REVISIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def mark_reviewed(
        self,
        rule_id:      str,
        approved:     bool,
        reviewer:     str,
        notes:        str = "",
    ) -> ReviewResult:
        """
        Marca una regla como revisada (aprobada o rechazada).

        Flujo de revisión:
          pending → approved  (reviewer confirma que la regla es correcta)
          pending → rejected  (reviewer la descarta como incorrecta/redundante)
          approved → rejected (corrección posterior)

        Args:
            rule_id:  ID de la regla (GEN-SQL-001).
            approved: True = approved, False = rejected.
            reviewer: Nombre/email del revisor.
            notes:    Notas de revisión (opcional pero recomendado).

        Returns:
            ReviewResult con el resultado.
        """
        if not self.is_available:
            return ReviewResult(
                success=False,
                rule_id=rule_id,
                error="MongoDB no disponible",
            )

        new_status = REVIEW_STATUS_APPROVED if approved else REVIEW_STATUS_REJECTED
        now = _now_iso()

        try:
            result = self._get_collection().update_one(
                {"rule_id": rule_id},
                {
                    "$set": {
                        "review_status": new_status,
                        "reviewed_by":   reviewer,
                        "reviewed_at":   now,
                        "review_notes":  notes or None,
                        "updated_at":    now,
                    }
                },
            )

            if result.matched_count == 0:
                return ReviewResult(
                    success=False,
                    rule_id=rule_id,
                    error=f"Regla '{rule_id}' no encontrada en MongoDB.",
                )

            logger.info(
                "RuleRepository: regla '%s' marcada como '%s' por '%s'.",
                rule_id, new_status, reviewer,
            )
            return ReviewResult(
                success=True,
                rule_id=rule_id,
                new_status=new_status,
            )

        except PyMongoError as exc:
            logger.error("RuleRepository.mark_reviewed: %s", exc)
            return ReviewResult(
                success=False,
                rule_id=rule_id,
                error=str(exc),
            )

    def reset_to_pending(self, rule_id: str) -> ReviewResult:
        """
        Resetea el estado de revisión a 'pending'.
        Útil cuando se actualiza una regla después de la revisión.
        """
        if not self.is_available:
            return ReviewResult(
                success=False, rule_id=rule_id, error="MongoDB no disponible"
            )
        try:
            now = _now_iso()
            result = self._get_collection().update_one(
                {"rule_id": rule_id},
                {
                    "$set": {
                        "review_status": REVIEW_STATUS_PENDING,
                        "reviewed_by":   None,
                        "reviewed_at":   None,
                        "review_notes":  None,
                        "updated_at":    now,
                    }
                },
            )
            success = result.matched_count > 0
            return ReviewResult(
                success=success,
                rule_id=rule_id,
                new_status=REVIEW_STATUS_PENDING if success else None,
                error=None if success else f"Regla '{rule_id}' no encontrada.",
            )
        except PyMongoError as exc:
            return ReviewResult(success=False, rule_id=rule_id, error=str(exc))

    # ─────────────────────────────────────────────────────────────────────────
    #  ELIMINACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def delete_rule(self, rule_id: str) -> bool:
        """
        Elimina una regla del repositorio.

        Args:
            rule_id: ID de la regla a eliminar.

        Returns:
            True si se eliminó, False si no existía o hubo error.
        """
        if not self.is_available:
            return False
        try:
            result = self._get_collection().delete_one({"rule_id": rule_id})
            deleted = result.deleted_count > 0
            if deleted:
                logger.info("RuleRepository: regla '%s' eliminada.", rule_id)
            else:
                logger.warning(
                    "RuleRepository: regla '%s' no encontrada para eliminar.",
                    rule_id,
                )
            return deleted
        except PyMongoError as exc:
            logger.error("RuleRepository.delete_rule: %s", exc)
            return False

    def delete_rejected_rules(self) -> int:
        """
        Elimina todas las reglas rechazadas para limpiar el repositorio.

        Returns:
            Número de reglas eliminadas.
        """
        if not self.is_available:
            return 0
        try:
            result = self._get_collection().delete_many(
                {"review_status": REVIEW_STATUS_REJECTED}
            )
            count = result.deleted_count
            if count:
                logger.info(
                    "RuleRepository: %d reglas rechazadas eliminadas.", count
                )
            return count
        except PyMongoError as exc:
            logger.error("RuleRepository.delete_rejected_rules: %s", exc)
            return 0

    # ─────────────────────────────────────────────────────────────────────────
    #  EXPORTACIÓN PARA RULE LOADER
    # ─────────────────────────────────────────────────────────────────────────

    def export_for_rule_loader(
        self,
        only_approved: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Exporta las reglas en el formato que consume RuleLoader.

        RuleLoader espera una lista de dicts con los campos del engine
        (id, rule_type, symbol, vulnerability, etc.) — NO el documento
        completo de MongoDB con los campos de metadata.

        Args:
            only_approved: Si True (default), solo exporta reglas aprobadas.
                           Si False, exporta todas las reglas válidas.

        Returns:
            Lista de dicts en formato nativo del engine csharp-sast.
            Se puede pasar directamente a RuleLoader como custom rules.

        Uso:
            rules = repo.export_for_rule_loader()
            # Guardar como .py para RuleLoader
            # O cargar directamente: loader.custom_rules.extend(rules)
        """
        if not self.is_available:
            return []

        query: dict[str, Any] = {"is_valid": True}
        if only_approved:
            query["review_status"] = REVIEW_STATUS_APPROVED

        try:
            docs = list(
                self._get_collection()
                .find(query, {"_id": 0, "rule_data": 1, "rule_id": 1})
                .sort("confidence_ai", DESCENDING)
            )

            # Extraer solo rule_data (el dict nativo del engine)
            rules = []
            for doc in docs:
                rule_data = doc.get("rule_data")
                if isinstance(rule_data, dict):
                    rules.append(rule_data)

            logger.info(
                "RuleRepository: %d reglas exportadas para RuleLoader.",
                len(rules),
            )
            return rules

        except PyMongoError as exc:
            logger.error("RuleRepository.export_for_rule_loader: %s", exc)
            return []

    def export_to_json_file(
        self,
        output_path: Any,  # Path
        only_approved: bool = True,
    ) -> bool:
        """
        Exporta las reglas aprobadas a un archivo JSON.

        Args:
            output_path: Path donde guardar el JSON.
            only_approved: Si True, solo exporta aprobadas.

        Returns:
            True si se exportó correctamente.
        """
        import json
        from pathlib import Path

        rules = self.export_for_rule_loader(only_approved=only_approved)
        if not rules:
            logger.warning("RuleRepository: no hay reglas para exportar.")
            return False

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        export_data = {
            "schema_version": DOCUMENT_SCHEMA_VERSION,
            "exported_at":    _now_iso(),
            "total_rules":    len(rules),
            "only_approved":  only_approved,
            "rules":          rules,
        }

        with output.open("w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        logger.info(
            "RuleRepository: %d reglas exportadas a '%s'.",
            len(rules), output,
        )
        return True

    # ─────────────────────────────────────────────────────────────────────────
    #  ESTADÍSTICAS
    # ─────────────────────────────────────────────────────────────────────────

    def get_stats(self) -> RuleStats:
        """
        Calcula estadísticas completas del repositorio de reglas.

        Returns:
            RuleStats con conteos, distribuciones y métricas.
        """
        if not self.is_available:
            return RuleStats()

        try:
            collection = self._get_collection()
            stats = RuleStats()

            # Totales básicos
            stats.total             = collection.count_documents({})
            stats.pending_review    = collection.count_documents({"review_status": REVIEW_STATUS_PENDING})
            stats.approved          = collection.count_documents({"review_status": REVIEW_STATUS_APPROVED})
            stats.rejected          = collection.count_documents({"review_status": REVIEW_STATUS_REJECTED})
            stats.production_ready  = collection.count_documents(
                {"is_production_ready": True, "review_status": REVIEW_STATUS_APPROVED}
            )

            # Distribución por tipo de regla
            pipeline_type = [
                {"$group": {"_id": "$rule_type", "count": {"$sum": 1}}},
                {"$sort": {"count": DESCENDING}},
            ]
            for doc in collection.aggregate(pipeline_type):
                if doc["_id"]:
                    stats.by_type[doc["_id"]] = doc["count"]

            # Distribución por vulnerabilidad (solo sinks)
            pipeline_vuln = [
                {"$match": {"rule_type": "sink", "vulnerability": {"$ne": ""}}},
                {"$group": {"_id": "$vulnerability", "count": {"$sum": 1}}},
                {"$sort": {"count": DESCENDING}},
            ]
            for doc in collection.aggregate(pipeline_vuln):
                if doc["_id"]:
                    stats.by_vulnerability[doc["_id"]] = doc["count"]

            # Distribución por framework (top 10)
            pipeline_fw = [
                {"$unwind": "$frameworks"},
                {"$group": {"_id": "$frameworks", "count": {"$sum": 1}}},
                {"$sort": {"count": DESCENDING}},
                {"$limit": 10},
            ]
            for doc in collection.aggregate(pipeline_fw):
                if doc["_id"]:
                    stats.by_framework[doc["_id"]] = doc["count"]

            # Confianza promedio de la IA
            pipeline_conf = [
                {"$group": {"_id": None, "avg": {"$avg": "$confidence_ai"}}}
            ]
            for doc in collection.aggregate(pipeline_conf):
                stats.avg_confidence_ai = round(doc.get("avg", 0.0) or 0.0, 3)

            return stats

        except PyMongoError as exc:
            logger.error("RuleRepository.get_stats: %s", exc)
            return RuleStats()

    def get_stats_dict(self) -> dict[str, Any]:
        """Versión dict de get_stats() para serialización."""
        stats = self.get_stats()
        return {
            "total":             stats.total,
            "pending_review":    stats.pending_review,
            "approved":          stats.approved,
            "rejected":          stats.rejected,
            "production_ready":  stats.production_ready,
            "by_type":           stats.by_type,
            "by_vulnerability":  stats.by_vulnerability,
            "by_framework":      stats.by_framework,
            "avg_confidence_ai": stats.avg_confidence_ai,
            "summary":           stats.summary(),
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS DE CONVERSIÓN DE DOCUMENTOS
    # ─────────────────────────────────────────────────────────────────────────

    def _generated_rule_to_document(self, generated_rule: Any) -> dict[str, Any]:
        """
        Convierte un GeneratedRule de rule_generator.py al documento MongoDB.

        Mapea todos los campos del GeneratedRule al schema de la colección
        security_rules.

        Args:
            generated_rule: Instancia de GeneratedRule.

        Returns:
            Dict listo para insertar en MongoDB.
        """
        rule       = generated_rule.rule
        validation = generated_rule.validation
        now        = _now_iso()

        return {
            "schema_version":    DOCUMENT_SCHEMA_VERSION,
            "rule_id":           generated_rule.rule_id,
            "rule_type":         generated_rule.rule_type,
            "symbol":            generated_rule.symbol,
            "vulnerability":     rule.get("vulnerability", ""),
            "rule_data":         rule,
            "generated_at":      generated_rule.generated_at,
            "gemini_model":      generated_rule.gemini_model,
            "pattern_source":    generated_rule.pattern_source,
            "generation_id":     generated_rule.generation_id,
            "confidence_ai":     generated_rule.confidence_ai,
            "is_valid":          validation.is_valid,
            "is_production_ready": generated_rule.is_production_ready,
            "collisions":        generated_rule.collisions,
            "validation_errors": validation.errors,
            "validation_warnings": validation.warnings,
            "review_status":     REVIEW_STATUS_PENDING,
            "reviewed_by":       None,
            "reviewed_at":       None,
            "review_notes":      None,
            "frameworks":        rule.get("frameworks", []),
            "tags":              rule.get("tags", []),
            "version":           1,
            "created_at":        now,
            "updated_at":        now,
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  UTILIDADES
    # ─────────────────────────────────────────────────────────────────────────

    def count_rules(self, query: dict[str, Any] | None = None) -> int:
        """Cuenta reglas con un filtro opcional."""
        if not self.is_available:
            return 0
        try:
            return self._get_collection().count_documents(query or {})
        except PyMongoError:
            return 0

    def rule_exists(self, rule_id: str) -> bool:
        """True si existe una regla con ese rule_id."""
        if not self.is_available:
            return False
        try:
            return self._get_collection().count_documents(
                {"rule_id": rule_id}, limit=1
            ) > 0
        except PyMongoError:
            return False

    def symbol_exists(self, symbol: str) -> bool:
        """True si ya existe una regla con ese símbolo exacto."""
        if not self.is_available:
            return False
        try:
            return self._get_collection().count_documents(
                {"symbol": symbol}, limit=1
            ) > 0
        except PyMongoError:
            return False

    def get_status(self) -> dict[str, Any]:
        """Estado del repositorio."""
        return {
            "available":        self.is_available,
            "collection":       self._collection_name,
            "mongodb_connected": self._mongo.connected,
            "pymongo_installed": _PYMONGO_AVAILABLE,
            "total_rules":      self.count_rules() if self.is_available else 0,
        }

    def __repr__(self) -> str:
        status = "AVAILABLE" if self.is_available else "UNAVAILABLE"
        return (
            f"RuleRepository({status}, "
            f"collection={self._collection_name}, "
            f"rules={self.count_rules()})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS DE MÓDULO
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    """Retorna el timestamp actual en formato ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat()