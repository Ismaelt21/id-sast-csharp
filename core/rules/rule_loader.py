# =============================================================================
#  csharp-sast / core / rules / rule_loader.py
# =============================================================================
#
#  ENSAMBLADOR CENTRAL DE REGLAS SAST
#  ────────────────────────────────────
#  Punto de entrada único para cargar, combinar, filtrar y acceder a
#  todas las reglas del engine: sinks, sources y sanitizadores.
#
#  RESPONSABILIDADES:
#    1. Importar y consolidar los catálogos de los 3 módulos:
#         sinks/      → sql, command, xml, deserialization, ssrf, path,
#                        reflection, razor
#         sources/    → aspnet, wcf, console
#         sanitizers/ → encoding, validation, parameterization
#
#    2. Construir índices de acceso rápido O(1) por símbolo
#
#    3. Aplicar filtros por framework activo (reducir ruido)
#
#    4. Soportar reglas personalizadas (custom_path) que complementan
#       o sobreescriben las built-in
#
#    5. Exponer la interfaz que consume el pipeline:
#         TaintAnalyzer       → needs_rules() → list[dict]
#         PatternMatcher      → get_all_sink_rules()
#         FrameworkAnalyzer   → get_source_taint_labels()
#         VulnerabilityClassifier → get_sanitizer_confidence_map()
#
#  DISEÑO:
#    • Carga lazy con cache: las reglas se cargan la primera vez
#      que se solicitan y se cachean en memoria para el resto del proceso.
#    • Reload explícito: reload() borra el cache y fuerza recarga.
#    • Inmutabilidad: los catálogos son read-only después de cargar.
#    • Framework filtering: activar solo reglas relevantes al framework
#      detectado — mejora performance y reduce falsos positivos.
#
#  INTEGRACIÓN CON EL PIPELINE:
#    scanner.py
#      └── RuleLoader.load_all()
#            └── TaintAnalyzer(rules=rules, ...)
#            └── CSharpPatternMatcher(rules=rules)
#            └── FrameworkAnalyzer()
#
# =============================================================================

from __future__ import annotations

import importlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

# Tipos de regla válidos
RULE_TYPE_SINK        = "sink"
RULE_TYPE_SOURCE      = "source"
RULE_TYPE_SANITIZER   = "sanitizer"

# Tipos de vulnerabilidad soportados
VULNERABILITY_KINDS = {
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
    "UNKNOWN",
}

# Frameworks soportados para filtrado
SUPPORTED_FRAMEWORKS = {
    "generic",
    "aspnetcore",
    "aspnet_mvc",
    "wcf",
    "winforms",
    "ef_core",
    "ef6",
    "dapper",
    "signalr",
    "grpc",
    "console",
}

# Módulos de sinks a cargar (module_path, función_de_carga)
_SINK_MODULES: list[tuple[str, str]] = [
    ("core.rules.sinks.sql_sinks",             "get_sql_sink_rules"),
    ("core.rules.sinks.command_sinks",          "get_command_sink_rules"),
    ("core.rules.sinks.xml_sinks",              "get_xml_sink_rules"),
    ("core.rules.sinks.deserialization_sinks",  "get_deserialization_sink_rules"),
    ("core.rules.sinks.ssrf_sinks",             "get_ssrf_sink_rules"),
    ("core.rules.sinks.path_sinks",             "get_path_sink_rules"),
    ("core.rules.sinks.reflection_sinks",       "get_reflection_sink_rules"),
    ("core.rules.sinks.razor_sinks",            "get_razor_sink_rules"),
]

# Módulos de sources a cargar
_SOURCE_MODULES: list[tuple[str, str]] = [
    ("core.rules.sources.aspnet_sources",  "get_aspnet_source_rules"),
    ("core.rules.sources.wcf_sources",     "get_wcf_source_rules"),
    ("core.rules.sources.console_sources", "get_console_source_rules"),
]

# Módulos de sanitizadores a cargar
_SANITIZER_MODULES: list[tuple[str, str]] = [
    ("core.rules.sanitizers.encoding_sanitizers",        "get_encoding_sanitizer_rules"),
    ("core.rules.sanitizers.validation_sanitizers",      "get_validation_sanitizer_rules"),
    ("core.rules.sanitizers.parameterization_sanitizers","get_parameterization_sanitizer_rules"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  MODELO DE ESTADÍSTICAS DE CARGA
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleLoadStats:
    """Estadísticas de la carga de reglas. Útil para debug y logging."""
    total_rules:            int = 0
    sink_rules:             int = 0
    source_rules:           int = 0
    sanitizer_rules:        int = 0
    custom_rules:           int = 0
    framework_filtered:     int = 0
    duplicate_ids_removed:  int = 0
    load_errors:            list[str] = field(default_factory=list)
    load_time_ms:           float = 0.0

    def summary(self) -> str:
        return (
            f"RuleLoadStats("
            f"total={self.total_rules}, "
            f"sinks={self.sink_rules}, "
            f"sources={self.source_rules}, "
            f"sanitizers={self.sanitizer_rules}, "
            f"custom={self.custom_rules}, "
            f"filtered={self.framework_filtered}, "
            f"errors={len(self.load_errors)}, "
            f"time={self.load_time_ms:.0f}ms)"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  ÍNDICES DE ACCESO RÁPIDO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleIndex:
    """
    Índices pre-computados para acceso O(1) desde los analizadores.
    Construido por RuleLoader._build_indexes() después de cargar las reglas.
    """

    # ── Sinks ─────────────────────────────────────────────────────────────────
    # symbol_prefix → regla de sink (para PatternMatcher)
    sinks_by_symbol: dict[str, dict] = field(default_factory=dict)

    # vulnerability_kind → [reglas de sink]
    sinks_by_vulnerability: dict[str, list[dict]] = field(default_factory=dict)

    # framework → [reglas de sink aplicables]
    sinks_by_framework: dict[str, list[dict]] = field(default_factory=dict)

    # Conjunto de symbols de sinks (para preclasificación rápida)
    sink_symbol_set: set[str] = field(default_factory=set)

    # ── Sources ───────────────────────────────────────────────────────────────
    # symbol_prefix → taint_label (para TaintAnalyzer)
    source_taint_labels: dict[str, str] = field(default_factory=dict)

    # symbol_prefix → severity_multiplier
    source_severity_multipliers: dict[str, float] = field(default_factory=dict)

    # framework → [reglas de source]
    sources_by_framework: dict[str, list[dict]] = field(default_factory=dict)

    # Conjunto de symbols de sources
    source_symbol_set: set[str] = field(default_factory=set)

    # ── Sanitizadores ─────────────────────────────────────────────────────────
    # symbol_prefix → confidence (para TaintAnalyzer)
    sanitizer_confidence_map: dict[str, float] = field(default_factory=dict)

    # symbol_prefix → [vulnerability_kinds que sanitiza]
    sanitizer_vulnerability_map: dict[str, list[str]] = field(default_factory=dict)

    # sanitizer_type → [reglas]
    sanitizers_by_type: dict[str, list[dict]] = field(default_factory=dict)

    # Conjunto de symbols de sanitizadores
    sanitizer_symbol_set: set[str] = field(default_factory=set)

    # ── Reglas "siempre vulnerables" ──────────────────────────────────────────
    # Sinks que son SIEMPRE vulnerables sin importar los argumentos
    # (BinaryFormatter, CSharpScript, etc.)
    always_vulnerable_sinks: set[str] = field(default_factory=set)


# ─────────────────────────────────────────────────────────────────────────────
#  RULE LOADER PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class RuleLoader:
    """
    Cargador central de reglas SAST para el engine C#.

    Uso estándar (carga todas las reglas built-in):
        loader = RuleLoader()
        rules  = loader.load_all()

    Uso con reglas personalizadas:
        loader = RuleLoader(custom_path=Path("./my_rules"))
        rules  = loader.load_all()

    Uso con filtrado por framework (más eficiente):
        loader = RuleLoader(active_frameworks={"aspnetcore", "ef_core"})
        rules  = loader.load_all()

    Acceso a índices pre-computados:
        index = loader.index
        taint_label = index.source_taint_labels.get("Microsoft.AspNetCore.Http.IQueryCollection")
        confidence  = index.sanitizer_confidence_map.get("System.Data.SqlClient.SqlParameter")
    """

    def __init__(
        self,
        custom_path:      Path | None = None,
        active_frameworks: set[str] | None = None,
    ) -> None:
        """
        Args:
            custom_path: Directorio con archivos .py de reglas personalizadas.
                         Deben seguir la misma estructura que los módulos built-in.
            active_frameworks: Conjunto de frameworks activos para filtrar reglas.
                               None = cargar reglas de TODOS los frameworks.
        """
        self._custom_path       = custom_path
        self._active_frameworks = active_frameworks
        self._all_rules:   list[dict] | None = None
        self._index:       RuleIndex  | None = None
        self._stats:       RuleLoadStats | None = None

    # ─────────────────────────────────────────────────────────────────────────
    #  API PÚBLICA
    # ─────────────────────────────────────────────────────────────────────────

    def load_all(self) -> list[dict]:
        """
        Carga todas las reglas (built-in + custom) y construye los índices.

        Returns:
            Lista completa de reglas como dicts. Cada regla tiene al menos:
            {id, rule_type, symbol, name, ...}

        La primera llamada carga desde disco. Las siguientes usan el cache.
        """
        if self._all_rules is not None:
            return self._all_rules

        t0 = time.monotonic()
        stats = RuleLoadStats()

        # ── 1. Cargar sinks ───────────────────────────────────────────────────
        sink_rules = self._load_from_modules(_SINK_MODULES, "sinks", stats)
        stats.sink_rules = len(sink_rules)

        # ── 2. Cargar sources ─────────────────────────────────────────────────
        source_rules = self._load_from_modules(_SOURCE_MODULES, "sources", stats)
        stats.source_rules = len(source_rules)

        # ── 3. Cargar sanitizadores ───────────────────────────────────────────
        sanitizer_rules = self._load_from_modules(_SANITIZER_MODULES, "sanitizers", stats)
        stats.sanitizer_rules = len(sanitizer_rules)

        # ── 4. Cargar reglas personalizadas ───────────────────────────────────
        custom_rules: list[dict] = []
        if self._custom_path:
            custom_rules = self._load_custom_rules(self._custom_path, stats)
            stats.custom_rules = len(custom_rules)

        # ── 5. Combinar y deduplicar ──────────────────────────────────────────
        all_rules = sink_rules + source_rules + sanitizer_rules + custom_rules
        all_rules, dupes = self._deduplicate(all_rules)
        stats.duplicate_ids_removed = dupes

        # ── 6. Filtrar por framework activo ───────────────────────────────────
        if self._active_frameworks:
            before = len(all_rules)
            all_rules = self._filter_by_framework(all_rules, self._active_frameworks)
            stats.framework_filtered = before - len(all_rules)

        # ── 7. Validar integridad de reglas ───────────────────────────────────
        all_rules = self._validate_rules(all_rules, stats)

        # ── 8. Construir índices ──────────────────────────────────────────────
        self._index = self._build_indexes(all_rules)
        self._all_rules = all_rules

        stats.total_rules = len(all_rules)
        stats.load_time_ms = (time.monotonic() - t0) * 1000
        self._stats = stats

        logger.info("RuleLoader: %s", stats.summary())
        if stats.load_errors:
            for err in stats.load_errors:
                logger.warning("RuleLoader error: %s", err)

        return self._all_rules

    def reload(self) -> list[dict]:
        """
        Fuerza la recarga de todas las reglas desde disco.
        Útil durante desarrollo cuando se modifican los catálogos.
        """
        logger.info("RuleLoader: recargando reglas...")
        self._all_rules = None
        self._index     = None
        self._stats     = None
        return self.load_all()

    @property
    def index(self) -> RuleIndex:
        """Acceso al índice pre-computado. Carga las reglas si no están cargadas."""
        if self._index is None:
            self.load_all()
        return self._index  # type: ignore[return-value]

    @property
    def stats(self) -> RuleLoadStats | None:
        """Estadísticas de la última carga."""
        return self._stats

    # ─────────────────────────────────────────────────────────────────────────
    #  ACCESORES ESPECIALIZADOS (atajos para los analizadores)
    # ─────────────────────────────────────────────────────────────────────────

    def get_all_sink_rules(self) -> list[dict]:
        """Retorna todas las reglas de tipo sink."""
        return [r for r in self.load_all() if r.get("rule_type") == RULE_TYPE_SINK]

    def get_all_source_rules(self) -> list[dict]:
        """Retorna todas las reglas de tipo source."""
        return [r for r in self.load_all() if r.get("rule_type") == RULE_TYPE_SOURCE]

    def get_all_sanitizer_rules(self) -> list[dict]:
        """Retorna todas las reglas de tipo sanitizer."""
        return [r for r in self.load_all() if r.get("rule_type") == RULE_TYPE_SANITIZER]

    def get_sink_rules_for_vulnerability(self, vulnerability: str) -> list[dict]:
        """Retorna los sinks de un tipo específico de vulnerabilidad."""
        return self.index.sinks_by_vulnerability.get(vulnerability, [])

    def get_source_taint_labels(self) -> dict[str, str]:
        """
        Retorna mapa {symbol_prefix → taint_label} para el TaintAnalyzer.
        Construcción O(1) después de la carga inicial.
        """
        return self.index.source_taint_labels

    def get_source_severity_multipliers(self) -> dict[str, float]:
        """Retorna mapa {symbol_prefix → severity_multiplier}."""
        return self.index.source_severity_multipliers

    def get_sanitizer_confidence_map(self) -> dict[str, float]:
        """
        Retorna mapa {symbol_prefix → confidence} para el TaintAnalyzer.
        El TaintAnalyzer usa esto para decidir si el taint se interrumpe.
        """
        return self.index.sanitizer_confidence_map

    def get_sanitizer_vulnerability_map(self) -> dict[str, list[str]]:
        """
        Retorna mapa {symbol_prefix → [vulnerability_kinds]}.
        El TaintAnalyzer verifica que el sanitizador es relevante para el sink.
        """
        return self.index.sanitizer_vulnerability_map

    def get_always_vulnerable_sinks(self) -> set[str]:
        """
        Retorna el conjunto de symbols de sinks siempre vulnerables
        (BinaryFormatter, CSharpScript, etc.) — CRITICAL independientemente
        de los argumentos.
        """
        return self.index.always_vulnerable_sinks

    def is_known_sink(self, resolved_symbol: str | None) -> bool:
        """True si el símbolo resuelto es un sink conocido."""
        if not resolved_symbol:
            return False
        return any(
            resolved_symbol.startswith(prefix)
            for prefix in self.index.sink_symbol_set
        )

    def is_known_source(self, resolved_symbol: str | None) -> bool:
        """True si el símbolo resuelto es una source conocida."""
        if not resolved_symbol:
            return False
        return any(
            resolved_symbol.startswith(prefix)
            for prefix in self.index.source_symbol_set
        )

    def is_known_sanitizer(self, resolved_symbol: str | None) -> bool:
        """True si el símbolo resuelto es un sanitizador conocido."""
        if not resolved_symbol:
            return False
        return any(
            resolved_symbol.startswith(prefix)
            for prefix in self.index.sanitizer_symbol_set
        )

    def get_rule_by_id(self, rule_id: str) -> dict | None:
        """Retorna una regla por su ID. Retorna None si no existe."""
        return next(
            (r for r in self.load_all() if r.get("id") == rule_id),
            None,
        )

    def get_rules_by_framework(self, framework: str) -> list[dict]:
        """Retorna todas las reglas aplicables a un framework específico."""
        return [
            r for r in self.load_all()
            if framework in r.get("frameworks", [])
            or "generic" in r.get("frameworks", [])
        ]

    def get_rules_by_tag(self, tag: str) -> list[dict]:
        """Retorna todas las reglas que tienen un tag específico."""
        return [r for r in self.load_all() if tag in r.get("tags", [])]

    def get_sink_for_symbol(self, resolved_symbol: str) -> dict | None:
        """
        Retorna el sink que hace match con el símbolo resuelto.
        Busca por prefijo — retorna el match más específico (mayor longitud de prefijo).
        """
        best_match: dict | None = None
        best_len = 0

        for prefix, rule in self.index.sinks_by_symbol.items():
            if resolved_symbol.startswith(prefix) and len(prefix) > best_len:
                best_match = rule
                best_len   = len(prefix)

        return best_match

    def get_source_for_symbol(self, resolved_symbol: str) -> dict | None:
        """Retorna la source que hace match con el símbolo resuelto."""
        for rule in self.get_all_source_rules():
            if resolved_symbol.startswith(rule.get("symbol", "")):
                return rule
        return None

    def get_sanitizer_for_symbol(self, resolved_symbol: str) -> dict | None:
        """Retorna el sanitizador que hace match con el símbolo resuelto."""
        for rule in self.get_all_sanitizer_rules():
            if resolved_symbol.startswith(rule.get("symbol", "")):
                return rule
        return None

    def summary(self) -> str:
        """Retorna un resumen textual del estado actual del loader."""
        rules = self.load_all()
        sinks      = sum(1 for r in rules if r.get("rule_type") == RULE_TYPE_SINK)
        sources    = sum(1 for r in rules if r.get("rule_type") == RULE_TYPE_SOURCE)
        sanitizers = sum(1 for r in rules if r.get("rule_type") == RULE_TYPE_SANITIZER)
        return (
            f"RuleLoader(total={len(rules)}, "
            f"sinks={sinks}, sources={sources}, sanitizers={sanitizers}, "
            f"frameworks={self._active_frameworks or 'all'})"
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  CARGA DESDE MÓDULOS
    # ─────────────────────────────────────────────────────────────────────────

    def _load_from_modules(
        self,
        modules: list[tuple[str, str]],
        category: str,
        stats: RuleLoadStats,
    ) -> list[dict]:
        """
        Carga reglas importando dinámicamente cada módulo.

        Args:
            modules:  Lista de (module_path, function_name).
            category: "sinks" | "sources" | "sanitizers" (para logging).
            stats:    Objeto de estadísticas para registrar errores.

        Returns:
            Lista combinada de reglas de todos los módulos.
        """
        all_rules: list[dict] = []

        for module_path, func_name in modules:
            try:
                module = importlib.import_module(module_path)
                func   = getattr(module, func_name)
                rules  = func()

                if not isinstance(rules, list):
                    stats.load_errors.append(
                        f"{module_path}.{func_name}() no retornó list"
                    )
                    continue

                all_rules.extend(rules)
                logger.debug(
                    "RuleLoader: %s/%s cargado — %d reglas",
                    category, module_path.split(".")[-1], len(rules),
                )

            except ImportError as exc:
                stats.load_errors.append(
                    f"ImportError en {module_path}: {exc}"
                )
                logger.warning(
                    "RuleLoader: no se pudo importar %s — %s",
                    module_path, exc,
                )
            except AttributeError as exc:
                stats.load_errors.append(
                    f"AttributeError en {module_path}.{func_name}: {exc}"
                )
                logger.warning(
                    "RuleLoader: función %s no encontrada en %s — %s",
                    func_name, module_path, exc,
                )
            except Exception as exc:
                stats.load_errors.append(
                    f"Error cargando {module_path}: {exc}"
                )
                logger.error(
                    "RuleLoader: error inesperado cargando %s — %s",
                    module_path, exc,
                )

        return all_rules

    # ─────────────────────────────────────────────────────────────────────────
    #  CARGA DE REGLAS PERSONALIZADAS
    # ─────────────────────────────────────────────────────────────────────────

    def _load_custom_rules(
        self,
        custom_path: Path,
        stats: RuleLoadStats,
    ) -> list[dict]:
        """
        Carga reglas personalizadas desde archivos .py en custom_path.

        Los archivos deben definir una función get_rules() → list[dict]
        con la misma estructura que los catálogos built-in.

        Ejemplo de archivo custom: my_rules/custom_sqli.py
            def get_rules() -> list[dict]:
                return [
                    {
                        "id": "CUSTOM-SQL-001",
                        "rule_type": "sink",
                        "symbol": "MyCompany.Db.CustomCommand..ctor",
                        "name": "MyCompany CustomCommand",
                        "vulnerability": "SQL_INJECTION",
                        "tainted_args": [0],
                        "always_vulnerable": False,
                        "confidence": "high",
                        "severity": "CRITICAL",
                        "cwe": "CWE-89",
                        "cvss_base": 9.8,
                        "description": "...",
                        "remediation": "...",
                        "frameworks": ["generic"],
                        "tags": ["sql", "custom"],
                    }
                ]
        """
        custom_rules: list[dict] = []

        if not custom_path.exists():
            logger.warning(
                "RuleLoader: custom_path no existe: %s", custom_path
            )
            return custom_rules

        if not custom_path.is_dir():
            logger.warning(
                "RuleLoader: custom_path no es un directorio: %s", custom_path
            )
            return custom_rules

        for py_file in sorted(custom_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            try:
                import importlib.util
                spec   = importlib.util.spec_from_file_location(
                    f"custom_rules.{py_file.stem}", py_file
                )
                if spec is None or spec.loader is None:
                    continue

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)  # type: ignore[attr-defined]

                if not hasattr(module, "get_rules"):
                    logger.debug(
                        "RuleLoader: %s no tiene get_rules() — ignorado",
                        py_file.name,
                    )
                    continue

                rules = module.get_rules()
                if not isinstance(rules, list):
                    stats.load_errors.append(
                        f"get_rules() en {py_file} no retornó list"
                    )
                    continue

                # Marcar como custom para trazabilidad
                for rule in rules:
                    rule["_custom"] = True
                    rule["_source_file"] = str(py_file)

                custom_rules.extend(rules)
                logger.info(
                    "RuleLoader: reglas custom cargadas de %s — %d reglas",
                    py_file.name, len(rules),
                )

            except Exception as exc:
                stats.load_errors.append(
                    f"Error en regla custom {py_file}: {exc}"
                )
                logger.error(
                    "RuleLoader: error cargando regla custom %s — %s",
                    py_file, exc,
                )

        logger.info(
            "RuleLoader: %d reglas custom cargadas de %s",
            len(custom_rules), custom_path,
        )
        return custom_rules

    # ─────────────────────────────────────────────────────────────────────────
    #  DEDUPLICACIÓN
    # ─────────────────────────────────────────────────────────────────────────

    def _deduplicate(
        self,
        rules: list[dict],
    ) -> tuple[list[dict], int]:
        """
        Elimina reglas con IDs duplicados.

        Prioridad de deduplicación:
          1. Reglas custom (de custom_path) tienen prioridad sobre built-in.
          2. Entre reglas del mismo tipo, la última en la lista gana.

        Returns:
            (reglas_deduplicadas, número_de_duplicados_eliminados)
        """
        seen:    dict[str, dict] = {}
        dupes = 0

        for rule in rules:
            rule_id = rule.get("id", "")
            if not rule_id:
                # Reglas sin ID — asignar uno temporal y añadir
                rule["id"] = f"auto-{id(rule)}"
                seen[rule["id"]] = rule
                continue

            if rule_id in seen:
                dupes += 1
                # Las custom tienen prioridad
                if rule.get("_custom") and not seen[rule_id].get("_custom"):
                    logger.debug(
                        "RuleLoader: regla custom %s sobreescribe built-in",
                        rule_id,
                    )
                    seen[rule_id] = rule
                # Entre built-in, la última gana (no loguear — es normal)
                elif not rule.get("_custom"):
                    seen[rule_id] = rule
            else:
                seen[rule_id] = rule

        return list(seen.values()), dupes

    # ─────────────────────────────────────────────────────────────────────────
    #  FILTRADO POR FRAMEWORK
    # ─────────────────────────────────────────────────────────────────────────

    def _filter_by_framework(
        self,
        rules: list[dict],
        active_frameworks: set[str],
    ) -> list[dict]:
        """
        Filtra las reglas para incluir solo las relevantes al framework activo.

        Una regla se incluye si:
          • Tiene "generic" en frameworks (aplica a todos).
          • Tiene al menos un framework en común con active_frameworks.
        """
        filtered = []
        for rule in rules:
            frameworks = set(rule.get("frameworks", []))
            if "generic" in frameworks or frameworks & active_frameworks:
                filtered.append(rule)
        return filtered

    # ─────────────────────────────────────────────────────────────────────────
    #  VALIDACIÓN DE REGLAS
    # ─────────────────────────────────────────────────────────────────────────

    _REQUIRED_SINK_FIELDS    = {"id", "rule_type", "symbol", "vulnerability", "cwe"}
    _REQUIRED_SOURCE_FIELDS  = {"id", "rule_type", "symbol", "taint_label"}
    _REQUIRED_SAN_FIELDS     = {"id", "rule_type", "symbol", "sanitizes", "confidence"}

    def _validate_rules(
        self,
        rules: list[dict],
        stats: RuleLoadStats,
    ) -> list[dict]:
        """
        Valida la integridad de las reglas y elimina las malformadas.
        Una regla malformada podría causar errores silenciosos en los analizadores.
        """
        valid_rules: list[dict] = []

        for rule in rules:
            rule_type = rule.get("rule_type", "")
            rule_id   = rule.get("id", "?")

            try:
                if rule_type == RULE_TYPE_SINK:
                    missing = self._REQUIRED_SINK_FIELDS - set(rule.keys())
                    if missing:
                        stats.load_errors.append(
                            f"Sink {rule_id}: campos faltantes {missing}"
                        )
                        continue
                    # Verificar vulnerability conocida
                    vuln = rule.get("vulnerability", "")
                    if vuln not in VULNERABILITY_KINDS:
                        logger.warning(
                            "RuleLoader: sink %s tiene vulnerability desconocida '%s'",
                            rule_id, vuln,
                        )

                elif rule_type == RULE_TYPE_SOURCE:
                    missing = self._REQUIRED_SOURCE_FIELDS - set(rule.keys())
                    if missing:
                        stats.load_errors.append(
                            f"Source {rule_id}: campos faltantes {missing}"
                        )
                        continue

                elif rule_type == RULE_TYPE_SANITIZER:
                    missing = self._REQUIRED_SAN_FIELDS - set(rule.keys())
                    if missing:
                        stats.load_errors.append(
                            f"Sanitizer {rule_id}: campos faltantes {missing}"
                        )
                        continue
                    # Verificar que confidence está en [0,1]
                    conf = rule.get("confidence", 0)
                    if not 0.0 <= float(conf) <= 1.0:
                        stats.load_errors.append(
                            f"Sanitizer {rule_id}: confidence={conf} fuera de [0,1]"
                        )
                        continue

                else:
                    stats.load_errors.append(
                        f"Regla {rule_id}: rule_type desconocido '{rule_type}'"
                    )
                    continue

                valid_rules.append(rule)

            except Exception as exc:
                stats.load_errors.append(
                    f"Error validando regla {rule_id}: {exc}"
                )

        invalid = len(rules) - len(valid_rules)
        if invalid > 0:
            logger.warning(
                "RuleLoader: %d reglas eliminadas por validación.",
                invalid,
            )

        return valid_rules

    # ─────────────────────────────────────────────────────────────────────────
    #  CONSTRUCCIÓN DE ÍNDICES
    # ─────────────────────────────────────────────────────────────────────────

    def _build_indexes(self, rules: list[dict]) -> RuleIndex:
        """
        Construye todos los índices O(1) a partir de las reglas cargadas.
        Se llama una sola vez después de cargar y validar todas las reglas.
        """
        idx = RuleIndex()

        for rule in rules:
            rule_type = rule.get("rule_type")
            symbol    = rule.get("symbol", "")

            if rule_type == RULE_TYPE_SINK:
                self._index_sink(rule, symbol, idx)

            elif rule_type == RULE_TYPE_SOURCE:
                self._index_source(rule, symbol, idx)

            elif rule_type == RULE_TYPE_SANITIZER:
                self._index_sanitizer(rule, symbol, idx)

        logger.debug(
            "RuleLoader index: %d sinks, %d sources, %d sanitizers",
            len(idx.sink_symbol_set),
            len(idx.source_symbol_set),
            len(idx.sanitizer_symbol_set),
        )
        return idx

    def _index_sink(self, rule: dict, symbol: str, idx: RuleIndex) -> None:
        """Indexa una regla de sink."""
        idx.sinks_by_symbol[symbol] = rule
        idx.sink_symbol_set.add(symbol)

        vuln = rule.get("vulnerability", "UNKNOWN")
        idx.sinks_by_vulnerability.setdefault(vuln, []).append(rule)

        for fw in rule.get("frameworks", []):
            idx.sinks_by_framework.setdefault(fw, []).append(rule)

        if rule.get("always_vulnerable", False):
            idx.always_vulnerable_sinks.add(symbol)

    def _index_source(self, rule: dict, symbol: str, idx: RuleIndex) -> None:
        """Indexa una regla de source."""
        idx.source_symbol_set.add(symbol)
        idx.source_taint_labels[symbol] = rule.get("taint_label", "USER_INPUT")
        idx.source_severity_multipliers[symbol] = rule.get("severity_multiplier", 1.0)

        for fw in rule.get("frameworks", []):
            idx.sources_by_framework.setdefault(fw, []).append(rule)

    def _index_sanitizer(self, rule: dict, symbol: str, idx: RuleIndex) -> None:
        """Indexa una regla de sanitizador."""
        idx.sanitizer_symbol_set.add(symbol)
        idx.sanitizer_confidence_map[symbol] = float(rule.get("confidence", 0.0))
        idx.sanitizer_vulnerability_map[symbol] = rule.get("sanitizes", [])

        san_type = rule.get("sanitizer_type", "UNKNOWN")
        idx.sanitizers_by_type.setdefault(san_type, []).append(rule)


# ─────────────────────────────────────────────────────────────────────────────
#  INSTANCIA SINGLETON (opcional — para evitar recargar en el mismo proceso)
# ─────────────────────────────────────────────────────────────────────────────

_default_loader: RuleLoader | None = None


def get_default_loader(
    active_frameworks: set[str] | None = None,
    custom_path: Path | None = None,
) -> RuleLoader:
    """
    Retorna (o crea) la instancia singleton del RuleLoader.

    Útil cuando múltiples componentes del pipeline necesitan el mismo loader
    sin pasarlo explícitamente. El singleton se crea con los parámetros
    de la primera llamada.

    Para reiniciar con nuevos parámetros, llamar reset_default_loader() primero.
    """
    global _default_loader
    if _default_loader is None:
        _default_loader = RuleLoader(
            custom_path=custom_path,
            active_frameworks=active_frameworks,
        )
    return _default_loader


def reset_default_loader() -> None:
    """Reinicia el singleton — la próxima llamada a get_default_loader() creará uno nuevo."""
    global _default_loader
    _default_loader = None


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS DE CONVENIENCIA (API funcional)
#  Permiten usar el loader sin instanciarlo explícitamente.
# ─────────────────────────────────────────────────────────────────────────────

def load_all_rules(
    active_frameworks: set[str] | None = None,
    custom_path: Path | None = None,
) -> list[dict]:
    """Carga y retorna todas las reglas. Shortcut de RuleLoader().load_all()."""
    return get_default_loader(active_frameworks, custom_path).load_all()


def get_sink_rules() -> list[dict]:
    """Retorna todas las reglas de sink del loader por defecto."""
    return get_default_loader().get_all_sink_rules()


def get_source_rules() -> list[dict]:
    """Retorna todas las reglas de source del loader por defecto."""
    return get_default_loader().get_all_source_rules()


def get_sanitizer_rules() -> list[dict]:
    """Retorna todas las reglas de sanitizer del loader por defecto."""
    return get_default_loader().get_all_sanitizer_rules()


def is_sink(resolved_symbol: str | None) -> bool:
    """True si el símbolo es un sink conocido."""
    return get_default_loader().is_known_sink(resolved_symbol)


def is_source(resolved_symbol: str | None) -> bool:
    """True si el símbolo es una source conocida."""
    return get_default_loader().is_known_source(resolved_symbol)


def is_sanitizer(resolved_symbol: str | None) -> bool:
    """True si el símbolo es un sanitizador conocido."""
    return get_default_loader().is_known_sanitizer(resolved_symbol)