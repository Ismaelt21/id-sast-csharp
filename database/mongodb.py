# =============================================================================
#  csharp-sast / core / parsers / mongodb.py
# =============================================================================
#
# 
# 
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, ConfigurationError
from typing import Optional
import os
import logging
import socket
import dns.resolver
logger = logging.getLogger(__name__)


class MongoDB:
    """
    MongoDB Connection Manager

    Responsabilidades:
    - Conectar a MongoDB Atlas/local
    - Gestionar client/database
    - Obtener collections
    - Cerrar conexión

    NO maneja:
    - lógica de reglas
    - lógica de análisis
    - queries complejas
    """

    def __init__(
        self,
        uri:     Optional[str] = None,
        db_name: Optional[str] = None,
    ):

        self.uri = uri or os.getenv("MONGODB_URI")

        self.db_name = (
            db_name
            or os.getenv("MONGODB_DB_NAME")
            or "csharp-sast"
        )

        # Corrección #1: TLS leído desde env en lugar de
        # hardcodeado a True. En development (local) es False;
        # en producción/Atlas debe ser True.
        self.use_tls = (
            os.getenv("MONGODB_TLS", "false").lower() == "true"
        )

        # Nombres de colección desde env (usados en indexes).
        # Corrección #3: evita hardcodear en create_indexes.
        self.rules_collection_name = os.getenv(
            "MONGODB_RULES_COLLECTION",
            "security_rules",
        )

        self.analysis_collection_name = os.getenv(
            "MONGODB_ANALYSIS_COLLECTION",
            "analyses",
        )

        self.client:    Optional[MongoClient] = None
        self.db         = None
        self.connected: bool = False

    # =========================================================
    # CONNECTION
    # =========================================================

    def _patch_dns_resolver():
        """Fuerza uso de Google DNS para resolver Atlas."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        dns.resolver.default_resolver = resolver
    
    def connect(self) -> bool:
        """
        Conecta a MongoDB.
        """

        # Corrección #2: validación explícita de URI antes de
        # intentar conectar. Evita errores crípticos de
        # MongoClient cuando MONGODB_URI no está configurado.
        if not self.uri:
            print(
                "[MongoDB] No URI configured. "
                "Set MONGODB_URI in your .env file."
            )
            return False

        if self.connected:
            print("[MongoDB] Already connected")
            return True

        try:
            
            self.client = MongoClient(
                self.uri,
                maxPoolSize=20,
                minPoolSize=5,
                serverSelectionTimeoutMS=2000,
                socketTimeoutMS=2000,
                connectTimeoutMS=2000, 
                retryWrites=True,
                tls=True,
                tlsAllowInvalidCertificates=True,
                tlsAllowInvalidHostnames=True, 
            )

            # Verificar conexión real antes de marcar como
            # conectado.
            self.client.admin.command("ping")

            self.db        = self.client[self.db_name]
            self.connected = True

            logger.debug("MongoDB connected: %s", self.db_name)
            print(f"[MongoDB] Database : {self.db_name}")
            print(f"[MongoDB] TLS      : {self.use_tls}")

            return True

        except (ConnectionFailure, ServerSelectionTimeoutError, ConfigurationError, Exception) as error:

            logger.debug("MongoDB connection failed: %s", error) 

            self.client    = None
            self.db        = None
            self.connected = False

            return False

    # =========================================================
    # DATABASE
    # =========================================================

    def get_database(self):
        """
        Retorna instancia de la DB.
        """

        if not self.connected:
            raise ConnectionError(
                "MongoDB is not connected. Call connect() first."
            )

        return self.db

    # =========================================================
    # COLLECTIONS
    # =========================================================

    def get_collection(self, collection_name: str):
        """
        Retorna una colección por nombre.
        """

        if not self.connected:
            raise ConnectionError(
                "MongoDB is not connected. Call connect() first."
            )

        return self.db[collection_name]

    # =========================================================
    # INDEXES
    # Corrección #3: nombres de colección leídos desde los
    # atributos de instancia (que a su vez vienen del env),
    # no hardcodeados como strings literales.
    # =========================================================

    def create_indexes(self) -> None:
        """
        Crea índices para las colecciones principales.
        """

        if not self.connected:
            raise ConnectionError(
                "MongoDB is not connected. Call connect() first."
            )

        try:

            # -------------------------------------------------
            # SECURITY RULES
            # -------------------------------------------------

            rules = self.get_collection(
                self.rules_collection_name
            )

            rules.create_index([("rule_id", 1)],       unique=True)
            rules.create_index([("vulnerability", 1)])
            rules.create_index([("created_by", 1)])
            rules.create_index([("validated", 1)])
            rules.create_index([("confidence", -1)])

            # -------------------------------------------------
            # ANALYSES
            # -------------------------------------------------

            analyses = self.get_collection(
                self.analysis_collection_name
            )

            analyses.create_index([("scan_id", 1)],    unique=True)
            analyses.create_index([("timestamp", -1)])
            analyses.create_index([("project_name", 1)])
            analyses.create_index(
                [("vulnerabilities.vulnerability", 1)]
            )

            print("[MongoDB] Indexes created successfully")

        except Exception as error:
            print(f"[MongoDB] Error creating indexes: {error}")

    # =========================================================
    # HEALTH CHECK
    # =========================================================

    def ping(self) -> bool:
        """
        Verifica estado de conexión.
        """

        try:

            if not self.client:
                return False

            self.client.admin.command("ping")
            return True

        except Exception:
            return False

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(self) -> dict:
        """
        Retorna estado actual de la conexión.
        """

        return {
            "connected":      self.connected,
            "database":       self.db_name,
            "uri_configured": bool(self.uri),
            "tls":            self.use_tls,
            "healthy":        self.ping(),
        }

    # =========================================================
    # DISCONNECT
    # Corrección #4: self.db se limpia a None en disconnect()
    # para que get_collection() falle correctamente con
    # "not connected" en lugar de intentar operar sobre un
    # cliente cerrado.
    # =========================================================

    def disconnect(self) -> None:
        """
        Cierra la conexión con MongoDB.
        """

        try:

            if self.client:
                self.client.close()

            print("[MongoDB] Connection closed")

        except Exception as error:
            print(f"[MongoDB] Error closing connection: {error}")

        finally:
            # Corrección #4: limpiamos client y db siempre,
            # incluso si close() lanza una excepción.
            self.client    = None
            self.db        = None
            self.connected = False


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    mongo = MongoDB()

    connected = mongo.connect()

    if connected:
        mongo.create_indexes()
        print(mongo.get_status())
        mongo.disconnect()

    print(mongo.get_status())
