# =============================================================================
#  csharp-sast / core / parsers / framework_detector.py
# =============================================================================
#
#  DETECTOR DE FRAMEWORK .NET
#  ────────────────────────────
#  Determina qué framework(s) usa el proyecto a partir del ParsedCSharpModel.
#
#  POR QUÉ IMPORTA:
#    El conjunto de fuentes (sources) de input del atacante varía según el framework:
#      ASP.NET Core  → HttpContext.Request.Query, [FromBody], [FromQuery], ...
#      ASP.NET MVC   → System.Web.HttpRequest.QueryString, ...
#      WCF           → OperationContext.Current.IncomingMessageProperties, ...
#      WinForms      → TextBox.Text, DataGridView.Rows, ...
#      Console App   → Console.ReadLine(), args[], ...
#
#    Sin detección de framework, el engine generaría falsos negativos masivos
#    (sources no detectadas) o activaría reglas incorrectas.
#
#  FUENTES DE INFORMACIÓN:
#    1. metadata.framework_detected — lo que el bridge detectó en la compilación
#    2. NuGet references            — paquetes referenciados
#    3. Using directives             — namespaces importados
#    4. Class attributes            — [ApiController], [ServiceContract], etc.
#    5. Base classes                — herencia de ControllerBase, etc.
#    6. Method attributes           — [HttpGet], [OperationContract], etc.
#
#  RESULTADO:
#    FrameworkProfile con:
#      • frameworks detectados (puede haber más de uno, e.g. AspNetCore + EF Core)
#      • versión aproximada de cada framework
#      • nivel de confianza de la detección (para logging)
#      • reglas de sources a activar
#      • configuración especial (nullable annotations, minimal APIs, etc.)
#
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from .ast_importer import ClassInfo, MethodInfo, ParsedCSharpModel

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  ENUMS Y CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

class Framework(Enum):
    """Frameworks .NET con reglas SAST específicas."""
    ASPNET_CORE = "aspnetcore"
    ASPNET_MVC = "aspnet_mvc"
    WCF = "wcf"
    WIN_FORMS = "winforms"
    EF_CORE = "ef_core"
    EF6 = "ef6"
    DAPPER = "dapper"
    SIGNAL_R = "signalr"
    GRPC = "grpc"
    CONSOLE = "console"
    GENERIC = "generic"


class DetectionConfidence(Enum):
    HIGH = "high"       # Detección directa (atributo, herencia, NuGet)
    MEDIUM = "medium"   # Inferencia (naming convention, using directive)
    LOW = "low"         # Suposición basada en metadata del bridge


# ─────────────────────────────────────────────────────────────────────────────
#  MODELO DE RESULTADO
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FrameworkDetection:
    """Detección de un framework específico con metadatos."""
    framework: Framework
    confidence: DetectionConfidence
    version_hint: str | None  # "8.0", "6.0", etc. si se pudo detectar
    evidence: list[str]       # Evidencia que llevó a la detección (para debug)


@dataclass
class FrameworkProfile:
    """
    Perfil completo de frameworks del proyecto.
    Consumido por framework_analyzer.py para activar las reglas correctas.
    """
    primary_framework: Framework
    all_frameworks: list[FrameworkDetection]

    # Flags de features específicos (afectan reglas SAST)
    has_minimal_api: bool = False          # ASP.NET Core Minimal APIs
    has_razor_pages: bool = False          # Razor Pages (XSS rules)
    has_blazor: bool = False               # Blazor (component model)
    has_nullable_annotations: bool = False  # C# 8+ nullable context
    has_async_endpoints: bool = False      # Endpoints async (taint tracking)
    uses_model_binding: bool = False       # Model binding automático de ASP.NET
    uses_dependency_injection: bool = False # DI (afecta flujo de datos)

    # Reglas a activar (keys del catálogo de sources/sinks)
    active_source_rule_sets: list[str] = field(default_factory=list)
    active_sink_rule_sets: list[str] = field(default_factory=list)

    @property
    def is_web_framework(self) -> bool:
        return self.primary_framework in (
            Framework.ASPNET_CORE, Framework.ASPNET_MVC,
            Framework.WCF, Framework.GRPC,
        )

    @property
    def frameworks_str(self) -> str:
        return ", ".join(d.framework.value for d in self.all_frameworks)

    def has_framework(self, fw: Framework) -> bool:
        return any(d.framework == fw for d in self.all_frameworks)

    def get_detection(self, fw: Framework) -> FrameworkDetection | None:
        return next((d for d in self.all_frameworks if d.framework == fw), None)

    def summary(self) -> str:
        return (
            f"FrameworkProfile(primary={self.primary_framework.value}, "
            f"all=[{self.frameworks_str}], "
            f"web={self.is_web_framework}, "
            f"async={self.has_async_endpoints})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  DETECTOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class FrameworkDetector:
    """
    Analiza el ParsedCSharpModel para determinar el framework .NET en uso.

    Uso:
        detector = FrameworkDetector()
        profile = detector.detect(model)
        if profile.has_framework(Framework.ASPNET_CORE):
            # activar reglas de ASP.NET Core
    """

    # NuGet packages → Framework
    _NUGET_TO_FRAMEWORK: dict[str, Framework] = {
        "Microsoft.AspNetCore":                    Framework.ASPNET_CORE,
        "Microsoft.AspNetCore.Mvc":                Framework.ASPNET_CORE,
        "Microsoft.AspNetCore.App":                Framework.ASPNET_CORE,
        "Microsoft.AspNetCore.Routing":            Framework.ASPNET_CORE,
        "Microsoft.AspNetCore.Http":               Framework.ASPNET_CORE,
        "System.Web.Mvc":                          Framework.ASPNET_MVC,
        "System.ServiceModel":                     Framework.WCF,
        "System.Windows.Forms":                    Framework.WIN_FORMS,
        "Microsoft.EntityFrameworkCore":           Framework.EF_CORE,
        "EntityFramework":                         Framework.EF6,
        "Dapper":                                  Framework.DAPPER,
        "Microsoft.AspNetCore.SignalR":            Framework.SIGNAL_R,
        "Grpc.AspNetCore":                         Framework.GRPC,
        "Google.Protobuf":                         Framework.GRPC,
    }

    # Namespaces en using → Framework
    _USING_TO_FRAMEWORK: dict[str, Framework] = {
        "Microsoft.AspNetCore.Mvc":                Framework.ASPNET_CORE,
        "Microsoft.AspNetCore.Http":               Framework.ASPNET_CORE,
        "Microsoft.AspNetCore.Routing":            Framework.ASPNET_CORE,
        "System.Web.Mvc":                          Framework.ASPNET_MVC,
        "System.Web.Http":                         Framework.ASPNET_MVC,
        "System.ServiceModel":                     Framework.WCF,
        "System.Windows.Forms":                    Framework.WIN_FORMS,
        "Microsoft.EntityFrameworkCore":           Framework.EF_CORE,
        "System.Data.Entity":                      Framework.EF6,
        "Dapper":                                  Framework.DAPPER,
        "Microsoft.AspNetCore.SignalR":            Framework.SIGNAL_R,
        "Grpc.AspNetCore":                         Framework.GRPC,
    }

    # Atributos de clase → Framework
    _CLASS_ATTR_TO_FRAMEWORK: dict[str, Framework] = {
        "ApiControllerAttribute":                  Framework.ASPNET_CORE,
        "ControllerAttribute":                     Framework.ASPNET_CORE,
        "RouteAttribute":                          Framework.ASPNET_CORE,
        "ServiceContractAttribute":                Framework.WCF,
    }

    # Atributos de método → Framework
    _METHOD_ATTR_TO_FRAMEWORK: dict[str, Framework] = {
        "HttpGetAttribute":                        Framework.ASPNET_CORE,
        "HttpPostAttribute":                       Framework.ASPNET_CORE,
        "HttpPutAttribute":                        Framework.ASPNET_CORE,
        "HttpDeleteAttribute":                     Framework.ASPNET_CORE,
        "HttpPatchAttribute":                      Framework.ASPNET_CORE,
        "OperationContractAttribute":              Framework.WCF,
        "WebMethodAttribute":                      Framework.ASPNET_MVC,
    }

    # Base classes que indican framework
    _BASE_CLASS_PATTERNS: list[tuple[str, Framework]] = [
        ("Microsoft.AspNetCore.Mvc.ControllerBase", Framework.ASPNET_CORE),
        ("Microsoft.AspNetCore.Mvc.Controller",     Framework.ASPNET_CORE),
        ("System.Web.Mvc.Controller",               Framework.ASPNET_MVC),
        ("System.Web.UI.Page",                      Framework.ASPNET_MVC),
        ("System.Windows.Forms.Form",               Framework.WIN_FORMS),
        ("System.Windows.Forms.UserControl",        Framework.WIN_FORMS),
    ]

    # Rules sets por framework
    _FRAMEWORK_SOURCE_RULES: dict[Framework, list[str]] = {
        Framework.ASPNET_CORE: ["aspnetcore_sources", "general_sources"],
        Framework.ASPNET_MVC:  ["aspnet_mvc_sources", "general_sources"],
        Framework.WCF:         ["wcf_sources", "general_sources"],
        Framework.WIN_FORMS:   ["winforms_sources", "general_sources"],
        Framework.CONSOLE:     ["console_sources"],
        Framework.GENERIC:     ["general_sources"],
    }

    _FRAMEWORK_SINK_RULES: dict[Framework, list[str]] = {
        Framework.ASPNET_CORE: ["sql_sinks", "command_sinks", "path_sinks",
                                 "deserialization_sinks", "ssrf_sinks", "razor_sinks",
                                 "xml_sinks", "reflection_sinks"],
        Framework.ASPNET_MVC:  ["sql_sinks", "command_sinks", "path_sinks",
                                 "deserialization_sinks", "ssrf_sinks"],
        Framework.WCF:         ["sql_sinks", "command_sinks", "deserialization_sinks"],
        Framework.GENERIC:     ["sql_sinks", "command_sinks", "path_sinks",
                                 "deserialization_sinks", "xml_sinks"],
    }

    def detect(self, model: ParsedCSharpModel) -> FrameworkProfile:
        """
        Analiza el modelo y retorna el FrameworkProfile completo.

        La detección tiene múltiples capas con diferentes niveles de confianza:
          1. Usar lo que Roslyn detectó (metadata del bridge) — HIGH
          2. Analizar NuGet references — HIGH
          3. Analizar using directives — MEDIUM
          4. Analizar atributos de clases/métodos — HIGH
          5. Analizar herencia de clases — HIGH
          6. Fallback: inferir por código — LOW
        """
        detections: dict[Framework, FrameworkDetection] = {}

        # ── 1. Framework del bridge (Roslyn lo detectó en tiempo de compilación) ─
        self._detect_from_bridge_metadata(model, detections)

        # ── 2. NuGet references ────────────────────────────────────────────────
        self._detect_from_nuget_refs(model, detections)

        # ── 3. Using directives ────────────────────────────────────────────────
        compilation_unit = model.classes  # usings están en metadata implícitamente
        self._detect_from_usings(model, detections)

        # ── 4. Atributos de clases ─────────────────────────────────────────────
        self._detect_from_class_attrs(model, detections)

        # ── 5. Herencia de clases ──────────────────────────────────────────────
        self._detect_from_base_classes(model, detections)

        # ── 6. Atributos de métodos ────────────────────────────────────────────
        self._detect_from_method_attrs(model, detections)

        # ── 7. ORM y data access patterns ─────────────────────────────────────
        self._detect_orm_frameworks(model, detections)

        # ── 8. Si no se detectó nada, usar CONSOLE o GENERIC ──────────────────
        if not detections:
            self._infer_fallback_framework(model, detections)

        # ── Determinar el framework primario (el de mayor confianza/relevancia) ─
        primary = self._select_primary_framework(detections)

        # ── Construir el perfil ────────────────────────────────────────────────
        profile = self._build_profile(primary, list(detections.values()), model)

        logger.info(
            "Framework detectado: %s (confianza: %s). Frameworks adicionales: [%s]",
            primary.framework.value,
            primary.confidence.value,
            ", ".join(
                d.framework.value
                for d in detections.values()
                if d.framework != primary.framework
            ),
        )
        return profile

    # ─────────────────────────────────────────────────────────────────────────
    #  DETECTORES POR CAPA
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_from_bridge_metadata(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """Usa el framework detectado por el bridge Roslyn durante la compilación."""
        fw_str = model.metadata.framework_detected
        if not fw_str:
            return

        fw_map = {
            "aspnetcore": Framework.ASPNET_CORE,
            "aspnet_mvc": Framework.ASPNET_MVC,
            "wcf":        Framework.WCF,
            "winforms":   Framework.WIN_FORMS,
            "ef_core":    Framework.EF_CORE,
        }

        fw = fw_map.get(fw_str.lower())
        if fw and fw not in detections:
            detections[fw] = FrameworkDetection(
                framework=fw,
                confidence=DetectionConfidence.HIGH,
                version_hint=None,
                evidence=[f"Bridge metadata: framework_detected='{fw_str}'"],
            )

    def _detect_from_nuget_refs(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """Detecta frameworks por referencias NuGet."""
        for ref in model.metadata.nuget_references:
            # ref formato: "PackageName/Version"
            package_name = ref.split("/")[0]
            version = ref.split("/")[1] if "/" in ref else None

            for prefix, fw in self._NUGET_TO_FRAMEWORK.items():
                if package_name.startswith(prefix):
                    if fw not in detections:
                        detections[fw] = FrameworkDetection(
                            framework=fw,
                            confidence=DetectionConfidence.HIGH,
                            version_hint=version,
                            evidence=[f"NuGet reference: {ref}"],
                        )
                    else:
                        detections[fw].evidence.append(f"NuGet reference: {ref}")
                    break

    def _detect_from_usings(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """
        Detecta frameworks por los using directives del proyecto.
        Los usings están en el campo compilation_unit del JSON del bridge,
        pero el ast_importer no los expone aún directamente.
        Usamos los external_calls como proxy (las llamadas a symbols externos
        revelan los namespaces en uso).
        """
        namespaces_in_use: set[str] = set()

        # Extraer namespaces de los external_calls y semantic_nodes
        for call in model.external_calls:
            parts = call.resolved_symbol.split(".")
            if len(parts) >= 2:
                ns = ".".join(parts[:2])
                namespaces_in_use.add(ns)
                if len(parts) >= 3:
                    namespaces_in_use.add(".".join(parts[:3]))

        for using_ns, fw in self._USING_TO_FRAMEWORK.items():
            for ns in namespaces_in_use:
                if ns.startswith(using_ns):
                    if fw not in detections:
                        detections[fw] = FrameworkDetection(
                            framework=fw,
                            confidence=DetectionConfidence.MEDIUM,
                            version_hint=None,
                            evidence=[f"Namespace en uso: {ns}"],
                        )
                    break

    def _detect_from_class_attrs(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """Detecta frameworks por los atributos de las clases."""
        for cls in model.classes:
            for attr in cls.attributes:
                fw = self._CLASS_ATTR_TO_FRAMEWORK.get(attr)
                if fw and fw not in detections:
                    detections[fw] = FrameworkDetection(
                        framework=fw,
                        confidence=DetectionConfidence.HIGH,
                        version_hint=None,
                        evidence=[f"Atributo [{attr}] en clase {cls.name}"],
                    )

    def _detect_from_base_classes(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """Detecta frameworks por herencia de clases conocidas."""
        for cls in model.classes:
            if not cls.base_class:
                continue
            for base_pattern, fw in self._BASE_CLASS_PATTERNS:
                if base_pattern in cls.base_class:
                    if fw not in detections:
                        detections[fw] = FrameworkDetection(
                            framework=fw,
                            confidence=DetectionConfidence.HIGH,
                            version_hint=None,
                            evidence=[
                                f"Clase {cls.name} hereda de {cls.base_class}"
                            ],
                        )
                    break

    def _detect_from_method_attrs(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """Detecta frameworks por atributos de métodos."""
        for cls in model.classes:
            for method in cls.methods:
                for attr in method.attributes:
                    fw = self._METHOD_ATTR_TO_FRAMEWORK.get(attr)
                    if fw and fw not in detections:
                        detections[fw] = FrameworkDetection(
                            framework=fw,
                            confidence=DetectionConfidence.HIGH,
                            version_hint=None,
                            evidence=[
                                f"Atributo [{attr}] en método {cls.name}.{method.name}"
                            ],
                        )

    def _detect_orm_frameworks(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """
        Detecta ORMs y librerías de data access (Dapper, EF Core, EF6).
        Estos afectan los sinks disponibles (FromSqlRaw, Dapper.Execute, etc.).
        """
        for node in model.semantic_nodes:
            if not node.resolved_symbol:
                continue

            if "Microsoft.EntityFrameworkCore" in node.resolved_symbol:
                if Framework.EF_CORE not in detections:
                    detections[Framework.EF_CORE] = FrameworkDetection(
                        framework=Framework.EF_CORE,
                        confidence=DetectionConfidence.HIGH,
                        version_hint=None,
                        evidence=[f"Símbolo EF Core en {node.file}:{node.line}"],
                    )
                break

            if "System.Data.Entity" in node.resolved_symbol:
                if Framework.EF6 not in detections:
                    detections[Framework.EF6] = FrameworkDetection(
                        framework=Framework.EF6,
                        confidence=DetectionConfidence.HIGH,
                        version_hint=None,
                        evidence=[f"Símbolo EF6 en {node.file}:{node.line}"],
                    )
                break

            if "Dapper." in node.resolved_symbol:
                if Framework.DAPPER not in detections:
                    detections[Framework.DAPPER] = FrameworkDetection(
                        framework=Framework.DAPPER,
                        confidence=DetectionConfidence.HIGH,
                        version_hint=None,
                        evidence=[f"Símbolo Dapper en {node.file}:{node.line}"],
                    )
                break

    def _infer_fallback_framework(
        self, model: ParsedCSharpModel, detections: dict[Framework, FrameworkDetection]
    ) -> None:
        """
        Si no se detectó ningún framework específico, inferir CONSOLE o GENERIC.
        """
        # Detectar app de consola: tiene métodos Main o uso de Console.*
        has_main = any(
            m.name in ("Main", "EntryPoint")
            for cls in model.classes
            for m in cls.methods
        )
        has_console_calls = any(
            n.resolved_symbol and n.resolved_symbol.startswith("System.Console.")
            for n in model.semantic_nodes
        )

        if has_main or has_console_calls:
            detections[Framework.CONSOLE] = FrameworkDetection(
                framework=Framework.CONSOLE,
                confidence=DetectionConfidence.MEDIUM,
                version_hint=None,
                evidence=["Método Main detectado" if has_main else "Uso de System.Console.*"],
            )
        else:
            detections[Framework.GENERIC] = FrameworkDetection(
                framework=Framework.GENERIC,
                confidence=DetectionConfidence.LOW,
                version_hint=None,
                evidence=["No se detectó framework específico"],
            )

    # ─────────────────────────────────────────────────────────────────────────
    #  SELECCIÓN DEL FRAMEWORK PRIMARIO
    # ─────────────────────────────────────────────────────────────────────────

    # Prioridad de frameworks (1 = mayor prioridad)
    _FRAMEWORK_PRIORITY: dict[Framework, int] = {
        Framework.ASPNET_CORE: 1,
        Framework.ASPNET_MVC:  2,
        Framework.WCF:         3,
        Framework.WIN_FORMS:   4,
        Framework.GRPC:        5,
        Framework.SIGNAL_R:    6,
        Framework.EF_CORE:     7,
        Framework.EF6:         8,
        Framework.DAPPER:      9,
        Framework.CONSOLE:     10,
        Framework.GENERIC:     99,
    }

    def _select_primary_framework(
        self, detections: dict[Framework, FrameworkDetection]
    ) -> FrameworkDetection:
        """Selecciona el framework primario por prioridad y confianza."""
        if not detections:
            return FrameworkDetection(
                framework=Framework.GENERIC,
                confidence=DetectionConfidence.LOW,
                version_hint=None,
                evidence=["Ningún framework detectado"],
            )

        def sort_key(d: FrameworkDetection) -> tuple[int, int]:
            priority = self._FRAMEWORK_PRIORITY.get(d.framework, 50)
            confidence_score = {"high": 0, "medium": 1, "low": 2}[d.confidence.value]
            return (priority, confidence_score)

        return min(detections.values(), key=sort_key)

    # ─────────────────────────────────────────────────────────────────────────
    #  CONSTRUCCIÓN DEL PROFILE
    # ─────────────────────────────────────────────────────────────────────────

    def _build_profile(
        self,
        primary: FrameworkDetection,
        all_detections: list[FrameworkDetection],
        model: ParsedCSharpModel,
    ) -> FrameworkProfile:
        """Construye el FrameworkProfile final con todos los flags y reglas."""
        fw = primary.framework

        profile = FrameworkProfile(
            primary_framework=fw,
            all_frameworks=all_detections,
        )

        # Detectar features específicos
        profile.has_async_endpoints = self._has_async_endpoints(model)
        profile.uses_model_binding = self._uses_model_binding(model)
        profile.uses_dependency_injection = self._uses_di(model)
        profile.has_minimal_api = self._has_minimal_api(model)
        profile.has_razor_pages = self._has_razor_pages(model)
        profile.has_nullable_annotations = "CSharp8" in model.metadata.language_version or \
            model.metadata.language_version in ("CSharp9", "CSharp10", "CSharp11", "CSharp12", "Latest")

        # Seleccionar rule sets según frameworks detectados
        activated_source_rules: set[str] = set()
        activated_sink_rules: set[str] = set()

        for detection in all_detections:
            src_rules = self._FRAMEWORK_SOURCE_RULES.get(detection.framework, [])
            sink_rules = self._FRAMEWORK_SINK_RULES.get(detection.framework, [])
            activated_source_rules.update(src_rules)
            activated_sink_rules.update(sink_rules)

        # Siempre activar reglas genéricas
        activated_source_rules.add("general_sources")
        activated_sink_rules.update(["sql_sinks", "command_sinks", "path_sinks"])

        profile.active_source_rule_sets = sorted(activated_source_rules)
        profile.active_sink_rule_sets = sorted(activated_sink_rules)

        logger.debug("Profile construido: %s", profile.summary())
        return profile

    # ─────────────────────────────────────────────────────────────────────────
    #  DETECCIÓN DE FEATURES
    # ─────────────────────────────────────────────────────────────────────────

    def _has_async_endpoints(self, model: ParsedCSharpModel) -> bool:
        """True si hay métodos entry point asíncronos."""
        return any(
            m.is_async and m.is_entry_point
            for cls in model.classes
            for m in cls.methods
        )

    def _uses_model_binding(self, model: ParsedCSharpModel) -> bool:
        """True si algún parámetro usa model binding de ASP.NET."""
        return any(
            param.is_http_bound
            for cls in model.classes
            for m in cls.methods
            for param in m.parameters
        )

    def _uses_di(self, model: ParsedCSharpModel) -> bool:
        """True si hay inyección de dependencias (constructores con interfaces)."""
        for cls in model.classes:
            for method in cls.methods:
                if method.name == cls.name:  # Es constructor
                    if any(
                        "I" in p.name or "Service" in p.resolved_type
                        for p in method.parameters
                    ):
                        return True
        return False

    def _has_minimal_api(self, model: ParsedCSharpModel) -> bool:
        """
        True si el proyecto usa Minimal APIs de ASP.NET Core 6+.
        Heurística: presencia de MapGet/MapPost/MapPut/MapDelete en external calls.
        """
        minimal_api_methods = {"MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch"}
        return any(
            any(m in call.resolved_symbol for m in minimal_api_methods)
            for call in model.external_calls
        )

    def _has_razor_pages(self, model: ParsedCSharpModel) -> bool:
        """True si hay Razor Pages (clases que heredan de PageModel)."""
        return any(
            cls.base_class and "PageModel" in cls.base_class
            for cls in model.classes
        )


# ─────────────────────────────────────────────────────────────────────────────
#  MAPEO DE FRAMEWORK PROFILE A REGLAS DE ANÁLISIS
# ─────────────────────────────────────────────────────────────────────────────

class FrameworkRuleMapper:
    """
    Convierte un FrameworkProfile a la configuración de reglas
    que debe usar el engine de análisis.

    Usado por framework_analyzer.py para seleccionar qué sources,
    sinks y sanitizadores son relevantes para el proyecto.
    """

    def get_source_taint_labels(self, profile: FrameworkProfile) -> dict[str, str]:
        """
        Retorna los símbolos fuente y sus labels de taint para el framework detectado.

        Returns:
            Dict {resolved_symbol_prefix: taint_label}
        """
        sources: dict[str, str] = {}

        if profile.has_framework(Framework.ASPNET_CORE):
            sources.update({
                "Microsoft.AspNetCore.Http.IQueryCollection":    "USER_INPUT",
                "Microsoft.AspNetCore.Http.IFormCollection":     "USER_INPUT",
                "Microsoft.AspNetCore.Http.IHeaderDictionary":   "USER_INPUT",
                "Microsoft.AspNetCore.Http.HttpRequest.Query":   "USER_INPUT",
                "Microsoft.AspNetCore.Http.HttpRequest.Form":    "USER_INPUT",
                "Microsoft.AspNetCore.Http.HttpRequest.Headers": "USER_INPUT",
                "Microsoft.AspNetCore.Http.HttpRequest.Body":    "USER_INPUT",
                "Microsoft.AspNetCore.Http.HttpRequest.Path":    "USER_INPUT",
                "Microsoft.AspNetCore.Routing.RouteData":        "USER_INPUT",
            })

        if profile.has_framework(Framework.ASPNET_MVC):
            sources.update({
                "System.Web.HttpRequest.QueryString":   "USER_INPUT",
                "System.Web.HttpRequest.Form":          "USER_INPUT",
                "System.Web.HttpRequest.Headers":       "USER_INPUT",
                "System.Web.HttpRequest.Cookies":       "USER_INPUT",
                "System.Web.HttpRequest.ServerVariables": "USER_INPUT",
                "System.Web.HttpRequest.InputStream":   "USER_INPUT",
            })

        if profile.has_framework(Framework.WCF):
            sources.update({
                "System.ServiceModel.OperationContext": "USER_INPUT",
                "System.ServiceModel.Channels.Message": "USER_INPUT",
            })

        if profile.has_framework(Framework.WIN_FORMS):
            sources.update({
                "System.Windows.Forms.TextBox.Text":        "USER_INPUT",
                "System.Windows.Forms.RichTextBox.Text":    "USER_INPUT",
                "System.Windows.Forms.ComboBox.Text":       "USER_INPUT",
                "System.Windows.Forms.DataGridView":        "USER_INPUT",
            })

        if profile.has_framework(Framework.CONSOLE):
            sources.update({
                "System.Console.ReadLine":                   "USER_INPUT",
                "System.Console.In":                         "USER_INPUT",
                "System.Environment.GetCommandLineArgs":     "USER_INPUT",
            })

        # Siempre incluir fuentes generales
        sources.update({
            "System.IO.StreamReader.ReadToEnd":     "EXTERNAL_INPUT",
            "System.IO.StreamReader.ReadLine":      "EXTERNAL_INPUT",
            "System.Net.WebClient.DownloadString":  "EXTERNAL_INPUT",
        })

        return sources

    def get_framework_specific_sinks(self, profile: FrameworkProfile) -> dict[str, str]:
        """
        Retorna sinks adicionales específicos del framework detectado.

        Returns:
            Dict {resolved_symbol_prefix: vulnerability_type}
        """
        sinks: dict[str, str] = {}

        if profile.has_framework(Framework.ASPNET_CORE):
            sinks.update({
                "Microsoft.AspNetCore.Html.HtmlString":        "XSS",
                "Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperExtensions.Raw": "XSS",
            })

        if profile.has_framework(Framework.EF_CORE):
            sinks.update({
                "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw":       "SQL_INJECTION",
                "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw":    "SQL_INJECTION",
                "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlInterpolated": "SQL_INJECTION",
            })

        if profile.has_framework(Framework.DAPPER):
            sinks.update({
                "Dapper.SqlMapper.Execute":      "SQL_INJECTION",
                "Dapper.SqlMapper.Query":        "SQL_INJECTION",
                "Dapper.SqlMapper.QueryAsync":   "SQL_INJECTION",
                "Dapper.SqlMapper.ExecuteAsync": "SQL_INJECTION",
            })

        return sinks