from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    def load_dotenv(*args, **kwargs):  # type: ignore
        return False


BASE_DIR = Path(__file__).resolve().parents[4]
load_dotenv(BASE_DIR / ".env")


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() == "true"


def _path_env(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    if not raw:
        return default
    path = Path(raw)
    return path if path.is_absolute() else BASE_DIR / path


class Settings:
    BASE_DIR = BASE_DIR
    APP_NAME = os.getenv("APP_NAME", "id-sast-csharp")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    VERSION = "0.1.0"
    DEBUG = _bool_env("DEBUG", False)

    USE_GEMINI = _bool_env("USE_GEMINI", True)
    ENABLE_AI_ANALYSIS = _bool_env("ENABLE_AI_ANALYSIS", True)
    ENABLE_SEMANTIC_ANALYSIS = _bool_env("ENABLE_SEMANTIC_ANALYSIS", True)
    ENABLE_RULE_GENERATION = _bool_env("ENABLE_RULE_GENERATION", True)
    GOOGLE_GEMINI_API_KEY = os.getenv("GOOGLE_GEMINI_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

    USE_PERSISTENCE = _bool_env("USE_PERSISTENCE", True)
    MONGODB_URI = os.getenv("MONGODB_URI")
    MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "id_sast_csharp")
    MONGODB_RULES_COLLECTION = os.getenv("MONGODB_RULES_COLLECTION", "security_rules")
    MONGODB_ANALYSIS_COLLECTION = os.getenv("MONGODB_ANALYSIS_COLLECTION", "analyses")

    REPORTS_DIR = _path_env("REPORTS_DIR", BASE_DIR / "reports" / "output")
    STORAGE_DIR = _path_env("STORAGE_DIR", BASE_DIR / "storage")
    RULE_CACHE_DIR = _path_env("RULE_CACHE_DIR", STORAGE_DIR / "rules")
    TEMP_DIR = _path_env("TEMP_DIR", STORAGE_DIR / "temp")

    BLOCKED_DIRECTORIES = {".git", "__pycache__", "venv", ".venv", "node_modules"}

    @classmethod
    def initialize_directories(cls) -> None:
        for directory in (cls.REPORTS_DIR, cls.STORAGE_DIR, cls.RULE_CACHE_DIR, cls.TEMP_DIR):
            directory.mkdir(parents=True, exist_ok=True)
