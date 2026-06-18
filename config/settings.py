"""
settings.py
Centralized settings for csharp-sast.

Loads .env from the project root and exposes typed configuration values
used by modules that prefer a single settings import instead of os.getenv().
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv_file(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv_file(BASE_DIR / ".env")


def _resolve_path(env_key: str, default: Path) -> Path:
    raw = os.getenv(env_key)
    if not raw:
        return default

    path = Path(raw)
    if path.is_absolute():
        return path

    return BASE_DIR / path


def _bool_env(env_key: str, default: bool) -> bool:
    raw = os.getenv(env_key)
    if raw is None:
        return default
    return raw.lower() == "true"


def _int_env(env_key: str, default: int) -> int:
    raw = os.getenv(env_key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class Settings:
    APP_NAME = os.getenv("APP_NAME", "csharp-sast")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    VERSION = "1.0.0"

    DEBUG = _bool_env("DEBUG", False)

    BASE_DIR = BASE_DIR

    STORAGE_DIR = _resolve_path("STORAGE_DIR", BASE_DIR / "storage")
    REPORTS_DIR = _resolve_path("REPORTS_DIR", BASE_DIR / "reports" / "output")
    RULE_CACHE_DIR = _resolve_path("RULE_CACHE_DIR", BASE_DIR / "storage" / "rules")
    GENERATED_RULES_DIR = _resolve_path(
        "GENERATED_RULES_DIR",
        BASE_DIR / "storage" / "generated_rules",
    )
    TEMP_DIR = _resolve_path("TEMP_DIR", BASE_DIR / "storage" / "temp")

    GOOGLE_GEMINI_API_KEY = os.getenv("GOOGLE_GEMINI_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
    USE_GEMINI = _bool_env("USE_GEMINI", True)
    ENABLE_AI_ANALYSIS = _bool_env("ENABLE_AI_ANALYSIS", True)
    SEMANTIC_ANALYZER_ENABLED = _bool_env("SEMANTIC_ANALYZER_ENABLED", True)
    SEMANTIC_ANALYZER_MAX_FINDINGS = _int_env("SEMANTIC_ANALYZER_MAX_FINDINGS", 50)
    ENABLE_RULE_GENERATION = _bool_env("ENABLE_RULE_GENERATION", True)

    MONGODB_URI = os.getenv("MONGODB_URI")
    MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "csharp-sast")
    MONGODB_RULES_COLLECTION = os.getenv("MONGODB_RULES_COLLECTION", "security_rules")
    MONGODB_ANALYSIS_COLLECTION = os.getenv("MONGODB_ANALYSIS_COLLECTION", "analyses")
    MONGODB_TLS = _bool_env("MONGODB_TLS", False)
    USE_PERSISTENCE = _bool_env("USE_PERSISTENCE", True)

    ROSLYN_BRIDGE_URL = os.getenv("ROSLYN_BRIDGE_URL", "http://localhost:5100")
    ROSLYN_ANALYSIS_TIMEOUT = _int_env("ROSLYN_ANALYSIS_TIMEOUT", 300)
    ROSLYN_BRIDGE_AUTO_START = _bool_env("ROSLYN_BRIDGE_AUTO_START", True)
    ROSLYN_BRIDGE_EXE = os.getenv("ROSLYN_BRIDGE_EXE")

    ANALYSIS_TIMEOUT = _int_env("ANALYSIS_TIMEOUT", 30)
    MAX_WORKERS = _int_env("MAX_WORKERS", 4)

    EXPORT_JSON = _bool_env("EXPORT_JSON", True)
    EXPORT_HTML = _bool_env("EXPORT_HTML", True)
    EXPORT_SARIF = _bool_env("EXPORT_SARIF", True)
    EXPORT_CONSOLE = _bool_env("EXPORT_CONSOLE", True)

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    VERBOSE_LOGGING = _bool_env("VERBOSE_LOGGING", True)

    @classmethod
    def initialize_directories(cls) -> None:
        for directory in [
            cls.STORAGE_DIR,
            cls.REPORTS_DIR,
            cls.RULE_CACHE_DIR,
            cls.GENERATED_RULES_DIR,
            cls.TEMP_DIR,
        ]:
            directory.mkdir(parents=True, exist_ok=True)