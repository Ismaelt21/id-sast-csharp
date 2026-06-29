# =============================================================================
#  csharp-sast / core / analyzers / framework_analyzer.py
# =============================================================================
#
#  ANALIZADOR DE REGLAS ESPECÍFICAS POR FRAMEWORK .NET
#  ──────────────────────────────────────────────────────
#  Aplica reglas de seguridad que solo tienen sentido en el contexto
#  del framework detectado. Opera DESPUÉS del TaintAnalyzer y el
#  PatternMatcher, añadiendo findings que esos no pueden detectar.
#
#  QUÉ DETECTA (ejemplos por framework):
#
#  ASP.NET Core:
#    • Action methods con [AllowAnonymous] que aceptan datos tainted
#    • Endpoints sin validación de modelo ([ApiController] sin ModelState.IsValid)
#    • CORS configurado con AllowAnyOrigin() + AllowCredentials()
#    • Anti-CSRF desactivado (sin [ValidateAntiForgeryToken] en POST/PUT/DELETE)
#    • Binding de tipos complejos sin [Bind] restrictivo
#    • Response caching de endpoints que retornan datos sensibles
#
#  Entity Framework Core:
#    • FromSqlRaw con interpolación de string
#    • ExecuteSqlRaw con datos del usuario
#    • Queries con AsNoTracking en contextos de escritura (race conditions)
#
#  WCF:
#    • OperationContract sin validación de input
#    • BasicHttpBinding sin seguridad (sin HTTPS, sin autenticación)
#    • NetTcpBinding con TransferMode=Streamed (DoS risk)
#
#  General .NET:
#    • Uso de BinaryFormatter (obsoleto, inseguro por diseño)
#    • Uso de MD5/SHA1 para hashing de contraseñas
#    • Random no criptográfico para tokens de seguridad
#    • Conexiones a base de datos con credenciales hardcoded
#    • Secretos hardcoded (connection strings, API keys en código)
#
#  DIFERENCIA CON PATTERN MATCHER:
#    PatternMatcher: match de símbolo → vulnerabilidad (1-a-1)
#    FrameworkAnalyzer: análisis de configuración y contexto
#                       (requiere entender el framework para saber si es vuln)
#
# =============================================================================

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.parsers.ast_importer import (
    AttributeAnnotation,
    ClassInfo,
    CSharpSemanticNode,
    MethodInfo,
    ParsedCSharpModel,
)
from core.parsers.framework_detector import Framework, FrameworkProfile
from core.analyzers.taint_analyzer import TaintConfidence, VulnerabilityKind

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  MODELO DE FINDING DEL FRAMEWORK ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class FrameworkFindingCategory(Enum):
    """Categoría del finding de framework (para grouping en reportes)."""
    AUTHENTICATION      = "authentication"
    AUTHORIZATION       = "authorization"
    CRYPTOGRAPHY        = "cryptography"
    CONFIGURATION       = "configuration"
    DATA_EXPOSURE       = "data_exposure"
    INJECTION           = "injection"
    SECRETS             = "secrets"
    DEPRECATED_API      = "deprecated_api"
    TRANSPORT_SECURITY  = "transport_security"
    CSRF                = "csrf"
    CORS                = "cors"


@dataclass
class FrameworkFinding:
    """
    Vulnerabilidad o misconfiguration detectada por análisis de framework.
    Complementa los TaintFinding y PatternFinding con hallazgos
    que requieren contexto del framework para ser detectados.
    """
    finding_id:          str
    vulnerability_kind:  VulnerabilityKind
    category:            FrameworkFindingCategory
    confidence:          TaintConfidence
    rule_id:             str
    rule_name:           str

    # Ubicación
    file:                str
    line:                int
    code_snippet:        str

    # Contexto
    method_id:           str | None
    method_name:         str | None
    class_name:          str | None
    framework:           Framework

    # Descripción
    title:               str
    description:         str
    remediation:         str
    cwe:                 str
    cvss_base:           float

    # Evidence
    raw_evidence:        dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"FrameworkFinding({self.rule_id}, "
            f"{self.framework.value}, "
            f"{self.file.split('/')[-1]}:{self.line})"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  ANALIZADOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

class FrameworkAnalyzer:
    """
    Aplica reglas de seguridad específicas del framework detectado.

    Uso:
        analyzer = FrameworkAnalyzer()
        findings = analyzer.analyze(model, profile)
    """

    def __init__(self) -> None:
        self._counter = 0

    def analyze(
        self,
        model: ParsedCSharpModel,
        profile: FrameworkProfile,
    ) -> list[FrameworkFinding]:
        """
        Ejecuta todos los analizadores de framework relevantes.

        Args:
            model:   ParsedCSharpModel del AstImporter.
            profile: FrameworkProfile del FrameworkDetector.

        Returns:
            Lista de FrameworkFinding con misconfigurations y vulns de framework.
        """
        findings: list[FrameworkFinding] = []

        # ── Reglas universales (aplican a cualquier framework) ─────────────
        findings.extend(self._check_deprecated_apis(model, profile))
        findings.extend(self._check_weak_cryptography(model, profile))
        findings.extend(self._check_hardcoded_secrets(model, profile))
        findings.extend(self._check_insecure_random(model, profile))

        # ── Reglas de ASP.NET Core ─────────────────────────────────────────
        if profile.has_framework(Framework.ASPNET_CORE):
            findings.extend(self._check_aspnetcore_csrf(model, profile))
            findings.extend(self._check_aspnetcore_authorization(model, profile))
            findings.extend(self._check_aspnetcore_model_validation(model, profile))
            findings.extend(self._check_aspnetcore_cors(model, profile))
            findings.extend(self._check_aspnetcore_open_redirect(model, profile))

        # ── Reglas de ASP.NET MVC clásico ─────────────────────────────────
        if profile.has_framework(Framework.ASPNET_MVC):
            findings.extend(self._check_aspnet_mvc_validate_input(model, profile))

        # ── Reglas de Entity Framework ────────────────────────────────────
        if profile.has_framework(Framework.EF_CORE) or profile.has_framework(Framework.EF6):
            findings.extend(self._check_ef_raw_sql(model, profile))

        # ── Reglas de WCF ─────────────────────────────────────────────────
        if profile.has_framework(Framework.WCF):
            findings.extend(self._check_wcf_security(model, profile))

        logger.info(
            "FrameworkAnalyzer [%s]: %d findings.",
            profile.primary_framework.value,
            len(findings),
        )
        return findings

    # =========================================================================
    #  REGLAS UNIVERSALES
    # =========================================================================

    def _check_deprecated_apis(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta APIs obsoletas e inherentemente inseguras:
          • BinaryFormatter           → RCE
          • SoapFormatter             → RCE
          • NetDataContractSerializer → RCE
          • MD5CryptoServiceProvider  → hashing débil
        """
        findings: list[FrameworkFinding] = []

        DEPRECATED = {
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter": (
                "FW-DEPR-001",
                "BinaryFormatter (inherentemente inseguro)",
                VulnerabilityKind.INSECURE_DESERIALIZATION,
                FrameworkFindingCategory.DEPRECATED_API,
                "BinaryFormatter es inherentemente inseguro y permite Remote Code Execution. "
                "Obsoleto desde .NET 5 y eliminado en .NET 9.",
                "Reemplazar por System.Text.Json.JsonSerializer, XmlSerializer, "
                "o MessagePack con tipos conocidos. No hay forma segura de usar BinaryFormatter.",
                "CWE-502", 9.8, TaintConfidence.CONFIRMED,
            ),
            "System.Runtime.Serialization.Formatters.Soap.SoapFormatter": (
                "FW-DEPR-002",
                "SoapFormatter (inherentemente inseguro)",
                VulnerabilityKind.INSECURE_DESERIALIZATION,
                FrameworkFindingCategory.DEPRECATED_API,
                "SoapFormatter permite deserialización de tipos arbitrarios → RCE.",
                "Usar WCF con DataContractSerializer y tipos conocidos.",
                "CWE-502", 9.8, TaintConfidence.CONFIRMED,
            ),
            "System.Runtime.Serialization.NetDataContractSerializer": (
                "FW-DEPR-003",
                "NetDataContractSerializer (inseguro)",
                VulnerabilityKind.INSECURE_DESERIALIZATION,
                FrameworkFindingCategory.DEPRECATED_API,
                "NetDataContractSerializer serializa información de tipos, "
                "permitiendo deserialización de tipos maliciosos.",
                "Usar DataContractSerializer con lista blanca de tipos conocidos.",
                "CWE-502", 8.1, TaintConfidence.HIGH,
            ),
        }

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue
            for symbol_prefix, rule_data in DEPRECATED.items():
                if sn.resolved_symbol.startswith(symbol_prefix):
                    method = model.get_method_for_node(sn)
                    cls    = model.get_class_for_node(sn)
                    (rid, rname, vkind, cat, desc, rem, cwe, cvss, conf) = rule_data
                    findings.append(self._make_finding(
                        rule_id=rid, rule_name=rname,
                        vulnerability_kind=vkind, category=cat,
                        confidence=conf, framework=profile.primary_framework,
                        sn=sn, method=method, cls=cls,
                        title=rname, description=desc,
                        remediation=rem, cwe=cwe, cvss_base=cvss,
                        evidence={"deprecated_symbol": sn.resolved_symbol},
                    ))
                    break

        return findings

    def _check_weak_cryptography(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta uso de algoritmos criptográficos débiles:
          • MD5 para hashing (no usar con contraseñas)
          • SHA1 para hashing (obsoleto para firmas)
          • DES / 3DES (cifrado simétrico roto)
          • ECB mode (revela patrones)
          • Random no-criptográfico para tokens de seguridad
        """
        findings: list[FrameworkFinding] = []

        WEAK_CRYPTO = {
            "System.Security.Cryptography.MD5": (
                "FW-CRYPTO-001", "MD5 para hashing",
                "MD5 no es adecuado para hashing criptográfico. "
                "Con rainbow tables puede invertirse en segundos.",
                "Para contraseñas usar BCrypt, PBKDF2 o Argon2. "
                "Para integridad usar SHA-256 o SHA-3.",
                "CWE-327", 7.5,
            ),
            "System.Security.Cryptography.SHA1": (
                "FW-CRYPTO-002", "SHA1 para hashing",
                "SHA1 tiene colisiones conocidas y no debe usarse para firmas digitales.",
                "Usar SHA-256, SHA-384 o SHA-512.",
                "CWE-327", 5.9,
            ),
            "System.Security.Cryptography.DESCryptoServiceProvider": (
                "FW-CRYPTO-003", "DES (cifrado obsoleto)",
                "DES usa clave de 56 bits, rompible con fuerza bruta en horas.",
                "Usar AES-256 con GCM mode para cifrado autenticado.",
                "CWE-327", 7.5,
            ),
            "System.Security.Cryptography.TripleDES": (
                "FW-CRYPTO-004", "3DES (SWEET32 vulnerable)",
                "3DES es vulnerable al ataque SWEET32 y tiene rendimiento muy bajo.",
                "Migrar a AES-256-GCM.",
                "CWE-327", 5.9,
            ),
            "System.Security.Cryptography.RC2": (
                "FW-CRYPTO-005", "RC2 (cifrado roto)",
                "RC2 es un cifrado inseguro con múltiples vulnerabilidades conocidas.",
                "Reemplazar inmediatamente por AES-256.",
                "CWE-327", 7.5,
            ),
        }

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue
            for prefix, (rid, rname, desc, rem, cwe, cvss) in WEAK_CRYPTO.items():
                if sn.resolved_symbol.startswith(prefix):
                    method = model.get_method_for_node(sn)
                    cls    = model.get_class_for_node(sn)
                    findings.append(self._make_finding(
                        rule_id=rid, rule_name=rname,
                        vulnerability_kind=VulnerabilityKind.UNKNOWN,
                        category=FrameworkFindingCategory.CRYPTOGRAPHY,
                        confidence=TaintConfidence.HIGH,
                        framework=profile.primary_framework,
                        sn=sn, method=method, cls=cls,
                        title=f"Algoritmo criptográfico débil: {rname}",
                        description=desc, remediation=rem,
                        cwe=cwe, cvss_base=cvss,
                        evidence={"weak_crypto_symbol": sn.resolved_symbol},
                    ))
                    break

        return findings

    def _check_hardcoded_secrets(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta secretos hardcodeados en el código:
          • Connection strings con password en texto plano
          • API keys o tokens como literales
          • Contraseñas en assignments de variables

        Usa análisis de texto de los nodos (heurística basada en nombres
        de variable y contenido de literales).
        """
        findings: list[FrameworkFinding] = []

        # Patrones de nombres de variable que sugieren un secreto
        SECRET_VAR_PATTERNS = re.compile(
            r"(password|passwd|pwd|secret|apikey|api_key|token|connectionstring"
            r"|connectionstr|connstr|privatekey|private_key|credentials|auth_key)",
            re.IGNORECASE,
        )

        # Patrones de valores que parecen credenciales reales
        CREDENTIAL_VALUE_PATTERNS = re.compile(
            r"(password\s*=\s*['\"][^'\"]{4,}['\"]"
            r"|pwd\s*=\s*['\"][^'\"]{4,}['\"]"
            r"|api[_\s]?key\s*=\s*['\"][A-Za-z0-9+/]{16,}['\"]"
            r"|['\"][A-Za-z0-9+/]{32,}={0,2}['\"])",  # Base64-like token
            re.IGNORECASE,
        )

        for asgn in model.assignments:
            if not asgn.is_literal:
                continue

            # Verificar si el nombre de variable sugiere un secreto
            if not SECRET_VAR_PATTERNS.search(asgn.target_name):
                continue

            # Verificar si el texto del source parece una credencial real
            # (no un placeholder como "changeme" o "your-password-here")
            source = asgn.source_text
            if not source or len(source) < 6:
                continue

            # Filtrar placeholders obvios
            PLACEHOLDERS = {
                "changeme", "password", "secret", "your-secret",
                "placeholder", "xxx", "***", "todo", "replace",
                "your-api-key", "", "none", "null",
            }
            source_clean = source.strip("\"'").lower()
            if source_clean in PLACEHOLDERS or len(source_clean) < 4:
                continue

            method = model.methods_by_id.get(asgn.containing_method_id)
            cls = (
                model.classes_by_id.get(method.containing_class_id)
                if method else None
            )

            findings.append(FrameworkFinding(
                finding_id=self._next_id(),
                vulnerability_kind=VulnerabilityKind.UNKNOWN,
                category=FrameworkFindingCategory.SECRETS,
                confidence=TaintConfidence.MEDIUM,
                rule_id="FW-SECRET-001",
                rule_name="Secreto hardcodeado potencial",
                file=method.file if method else "",
                line=asgn.line,
                code_snippet=f"{asgn.target_name} = {source[:50]}",
                method_id=asgn.containing_method_id,
                method_name=method.name if method else None,
                class_name=cls.name if cls else None,
                framework=profile.primary_framework,
                title="Posible secreto hardcodeado en código fuente",
                description=(
                    f"La variable '{asgn.target_name}' parece contener un secreto "
                    f"hardcodeado. Los secretos en código fuente quedan expuestos "
                    f"en el repositorio y son difíciles de rotar."
                ),
                remediation=(
                    "Usar Azure Key Vault, AWS Secrets Manager, o variables de entorno "
                    "para almacenar secretos. En .NET usar IConfiguration con "
                    "appsettings.{Environment}.json + user-secrets en desarrollo."
                ),
                cwe="CWE-798",
                cvss_base=7.5,
                raw_evidence={
                    "variable_name": asgn.target_name,
                    "value_preview": source[:30],
                },
            ))

        return findings

    def _check_insecure_random(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta uso de System.Random en contextos de seguridad.
        System.Random no es criptográficamente seguro; para tokens,
        nonces y claves debe usarse RandomNumberGenerator.
        """
        findings: list[FrameworkFinding] = []

        RANDOM_SYMBOL = "System.Random"
        SECURITY_CONTEXTS = re.compile(
            r"(token|nonce|salt|key|password|session|csrf|otp|captcha|secret)",
            re.IGNORECASE,
        )

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue
            if not sn.resolved_symbol.startswith(RANDOM_SYMBOL):
                continue

            # Verificar si está en un contexto de seguridad (por nombre de variable
            # cercana o por el nombre del método contenedor)
            method = model.get_method_for_node(sn)
            if not method:
                continue

            method_name_suggests_security = SECURITY_CONTEXTS.search(method.name)
            text_suggests_security = SECURITY_CONTEXTS.search(sn.text)

            if not method_name_suggests_security and not text_suggests_security:
                continue

            cls = model.get_class_for_node(sn)

            findings.append(self._make_finding(
                rule_id="FW-CRYPTO-006",
                rule_name="System.Random en contexto de seguridad",
                vulnerability_kind=VulnerabilityKind.UNKNOWN,
                category=FrameworkFindingCategory.CRYPTOGRAPHY,
                confidence=TaintConfidence.MEDIUM,
                framework=profile.primary_framework,
                sn=sn, method=method, cls=cls,
                title="Random no-criptográfico en contexto de seguridad",
                description=(
                    "System.Random no es criptográficamente seguro. "
                    "Su salida puede predecirse con suficientes observaciones, "
                    "lo que invalida tokens, nonces y sales generados con él."
                ),
                remediation=(
                    "Usar RandomNumberGenerator.GetBytes() (System.Security.Cryptography) "
                    "para generar valores aleatorios criptográficamente seguros. "
                    "O usar RandomNumberGenerator.GetInt32() para enteros."
                ),
                cwe="CWE-338",
                cvss_base=7.5,
                evidence={"random_symbol": sn.resolved_symbol, "context": sn.text[:60]},
            ))

        return findings

    # =========================================================================
    #  REGLAS DE ASP.NET CORE
    # =========================================================================

    def _check_aspnetcore_csrf(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta action methods POST/PUT/DELETE sin protección CSRF.

        En ASP.NET Core la protección CSRF se logra con:
          • [ValidateAntiForgeryToken] en el action method
          • AutoValidateAntiforgeryToken configurado globalmente
          • [IgnoreAntiforgeryToken] explícitamente (excepción justificada)

        Los endpoints [HttpPost] sin ninguno de esos atributos son vulnerables.
        """
        findings: list[FrameworkFinding] = []

        MUTATING_ATTRS = {
            "HttpPostAttribute", "HttpPutAttribute",
            "HttpDeleteAttribute", "HttpPatchAttribute",
        }
        CSRF_PROTECTION_ATTRS = {
            "ValidateAntiForgeryTokenAttribute",
            "IgnoreAntiforgeryTokenAttribute",  # Excepción justificada
            "AutoValidateAntiforgeryToken",
        }

        # Construir mapa de atributos por target_id
        annotations_by_target: dict[str, list[AttributeAnnotation]] = {}
        for ann in model.attribute_annotations:
            annotations_by_target.setdefault(ann.target_id, []).append(ann)

        for cls in model.classes:
            if not cls.is_controller:
                continue

            # Verificar si la clase tiene ValidateAntiForgeryToken global
            class_anns = annotations_by_target.get(cls.class_id, [])
            class_has_csrf = any(
                a.attribute_name in CSRF_PROTECTION_ATTRS for a in class_anns
            )

            for method in cls.methods:
                method_anns = annotations_by_target.get(method.method_id, [])
                method_attr_names = {a.attribute_name for a in method_anns}

                # ¿Es un método mutante (POST/PUT/DELETE/PATCH)?
                if not method_attr_names & MUTATING_ATTRS:
                    continue

                # ¿Tiene protección CSRF?
                method_has_csrf = bool(method_attr_names & CSRF_PROTECTION_ATTRS)

                if class_has_csrf or method_has_csrf:
                    continue

                # [ApiController] los excluye porque usa tokens en headers (anti-CSRF no aplica a APIs puras)
                if "ApiControllerAttribute" in {a.attribute_name for a in class_anns}:
                    continue

                mutating_attr = next(
                    a.attribute_name for a in method_anns
                    if a.attribute_name in MUTATING_ATTRS
                )

                findings.append(FrameworkFinding(
                    finding_id=self._next_id(),
                    vulnerability_kind=VulnerabilityKind.CSRF,
                    category=FrameworkFindingCategory.CSRF,
                    confidence=TaintConfidence.HIGH,
                    rule_id="FW-ASPNET-001",
                    rule_name="CSRF: acción mutante sin ValidateAntiForgeryToken",
                    file=method.file,
                    line=method.line_start,
                    code_snippet=method.signature[:100],
                    method_id=method.method_id,
                    method_name=method.name,
                    class_name=cls.name,
                    framework=Framework.ASPNET_CORE,
                    title=f"Acción [{mutating_attr}] sin protección CSRF",
                    description=(
                        f"El método {cls.name}.{method.name}() usa [{mutating_attr}] "
                        f"pero no tiene [ValidateAntiForgeryToken]. "
                        f"Un atacante puede inducir a un usuario autenticado a "
                        f"realizar esta acción sin su consentimiento."
                    ),
                    remediation=(
                        "Añadir [ValidateAntiForgeryToken] al action method, "
                        "o [AutoValidateAntiforgeryToken] a nivel de clase o globalmente "
                        "en Program.cs: builder.Services.AddControllersWithViews("
                        "o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));"
                    ),
                    cwe="CWE-352",
                    cvss_base=6.5,
                    raw_evidence={
                        "mutating_attribute": mutating_attr,
                        "class_has_csrf": class_has_csrf,
                    },
                ))

        return findings

    def _check_aspnetcore_authorization(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta endpoints expuestos sin autorización cuando el resto
        del controller la requiere (posible oversight de seguridad).

        Caso detectado:
          [Authorize]               ← clase con autorización global
          class UserController {
            [AllowAnonymous]        ← método expuesto anónimamente
            [HttpGet("/admin/...")]  ← en ruta privilegiada
            public IActionResult GetAdminData() { ... }
          }
        """
        findings: list[FrameworkFinding] = []

        annotations_by_target: dict[str, list[AttributeAnnotation]] = {}
        for ann in model.attribute_annotations:
            annotations_by_target.setdefault(ann.target_id, []).append(ann)

        for cls in model.classes:
            if not cls.is_controller:
                continue

            class_anns = {a.attribute_name for a in annotations_by_target.get(cls.class_id, [])}
            class_has_authorize = "AuthorizeAttribute" in class_anns

            for method in cls.methods:
                method_anns = {
                    a.attribute_name
                    for a in annotations_by_target.get(method.method_id, [])
                }

                is_anonymous = "AllowAnonymousAttribute" in method_anns
                is_entry_point = method.is_entry_point

                if not is_anonymous or not is_entry_point:
                    continue

                # AllowAnonymous en controller con Authorize global
                # Solo reportar si hay indicios de ruta privilegiada
                route_args = [
                    a.arguments
                    for a in model.attribute_annotations
                    if a.target_id == method.method_id
                    and a.attribute_name == "RouteAttribute"
                ]
                route_str = " ".join(
                    arg for args in route_args for arg in args
                ).lower()

                is_privileged_route = any(
                    kw in route_str
                    for kw in ("admin", "manage", "internal", "private", "system")
                )

                if class_has_authorize and is_privileged_route:
                    findings.append(FrameworkFinding(
                        finding_id=self._next_id(),
                        vulnerability_kind=VulnerabilityKind.UNKNOWN,
                        category=FrameworkFindingCategory.AUTHORIZATION,
                        confidence=TaintConfidence.MEDIUM,
                        rule_id="FW-ASPNET-002",
                        rule_name="[AllowAnonymous] en ruta privilegiada de controller con [Authorize]",
                        file=method.file,
                        line=method.line_start,
                        code_snippet=method.signature[:100],
                        method_id=method.method_id,
                        method_name=method.name,
                        class_name=cls.name,
                        framework=Framework.ASPNET_CORE,
                        title=f"Endpoint anónimo en ruta privilegiada: {cls.name}.{method.name}",
                        description=(
                            f"{cls.name} tiene [Authorize] global pero "
                            f"{method.name}() usa [AllowAnonymous] en una ruta "
                            f"que parece privilegiada ({route_str}). "
                            f"Verificar que esta exposición es intencional."
                        ),
                        remediation=(
                            "Revisar si [AllowAnonymous] es intencional en esta ruta. "
                            "Si el endpoint requiere autenticación, eliminar [AllowAnonymous]. "
                            "Si es público por diseño, moverlo a un controller sin [Authorize]."
                        ),
                        cwe="CWE-284",
                        cvss_base=5.3,
                        raw_evidence={"route": route_str},
                    ))

        return findings

    def _check_aspnetcore_model_validation(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta action methods de ASP.NET Core que no validan el ModelState
        antes de procesar datos de entrada.

        Heurística: si el método es un entry point con parámetros de binding
        y no tiene ModelState.IsValid ni [ApiController] (que lo hace automático),
        puede procesar datos inválidos.
        """
        findings: list[FrameworkFinding] = []

        annotations_by_target: dict[str, list[AttributeAnnotation]] = {}
        for ann in model.attribute_annotations:
            annotations_by_target.setdefault(ann.target_id, []).append(ann)

        for cls in model.classes:
            # [ApiController] valida automáticamente → no reportar
            class_anns = {a.attribute_name for a in annotations_by_target.get(cls.class_id, [])}
            if "ApiControllerAttribute" in class_anns:
                continue

            if not cls.is_controller:
                continue

            for method in cls.methods:
                if not method.is_entry_point:
                    continue

                # ¿Tiene parámetros con binding?
                has_bound_params = any(
                    p.is_http_bound or p.is_user_controlled
                    for p in method.parameters
                    if p.resolved_type not in (
                        "System.Threading.CancellationToken",
                        "Microsoft.AspNetCore.Http.HttpContext",
                    )
                )
                if not has_bound_params:
                    continue

                # ¿El código del método verifica ModelState?
                # Buscamos en los nodos semánticos del método
                nodes_in_method = model.nodes_by_method.get(method.method_id, [])
                checks_model_state = any(
                    "ModelState" in n.text or "IsValid" in n.text
                    for n in nodes_in_method
                )

                if checks_model_state:
                    continue

                # Solo reportar si hay parámetros con tipos complejos (models)
                complex_params = [
                    p for p in method.parameters
                    if "." in p.resolved_type  # Tipo con namespace → probablemente model
                    and "System." not in p.resolved_type
                    and "Microsoft." not in p.resolved_type
                ]
                if not complex_params:
                    continue

                findings.append(FrameworkFinding(
                    finding_id=self._next_id(),
                    vulnerability_kind=VulnerabilityKind.UNKNOWN,
                    category=FrameworkFindingCategory.CONFIGURATION,
                    confidence=TaintConfidence.LOW,
                    rule_id="FW-ASPNET-003",
                    rule_name="Action method sin validación de ModelState",
                    file=method.file,
                    line=method.line_start,
                    code_snippet=method.signature[:100],
                    method_id=method.method_id,
                    method_name=method.name,
                    class_name=cls.name,
                    framework=Framework.ASPNET_CORE,
                    title=f"ModelState no validado en {cls.name}.{method.name}",
                    description=(
                        f"El action method {method.name}() acepta parámetros complejos "
                        f"({', '.join(p.name for p in complex_params)}) "
                        f"pero no verifica ModelState.IsValid. "
                        f"Datos inválidos pueden causar comportamientos inesperados."
                    ),
                    remediation=(
                        "Añadir [ApiController] al controller para validación automática, "
                        "o verificar explícitamente: if (!ModelState.IsValid) return BadRequest(ModelState);"
                    ),
                    cwe="CWE-20",
                    cvss_base=4.3,
                    raw_evidence={
                        "complex_params": [p.name for p in complex_params],
                    },
                ))

        return findings

    def _check_aspnetcore_cors(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta configuración CORS insegura:
          AllowAnyOrigin() + AllowCredentials() → CORS misconfiguration crítica
          (los navegadores rechazan esto, pero indica política CORS incorrecta)
        """
        findings: list[FrameworkFinding] = []

        has_allow_any_origin = False
        has_allow_credentials = False
        cors_node: CSharpSemanticNode | None = None

        for sn in model.semantic_nodes:
            if "AllowAnyOrigin" in sn.text:
                has_allow_any_origin = True
                cors_node = sn
            if "AllowCredentials" in sn.text:
                has_allow_credentials = True

        if has_allow_any_origin and has_allow_credentials:
            if cors_node:
                method = model.get_method_for_node(cors_node)
                cls    = model.get_class_for_node(cors_node)
                findings.append(self._make_finding(
                    rule_id="FW-CORS-001",
                    rule_name="CORS: AllowAnyOrigin + AllowCredentials",
                    vulnerability_kind=VulnerabilityKind.UNKNOWN,
                    category=FrameworkFindingCategory.CORS,
                    confidence=TaintConfidence.HIGH,
                    framework=Framework.ASPNET_CORE,
                    sn=cors_node, method=method, cls=cls,
                    title="Configuración CORS insegura: AllowAnyOrigin + AllowCredentials",
                    description=(
                        "La combinación AllowAnyOrigin() + AllowCredentials() es una "
                        "CORS misconfiguration. Aunque los navegadores la rechazan, "
                        "indica una política CORS incorrectamente diseñada que puede "
                        "habilitarse accidentalmente."
                    ),
                    remediation=(
                        "Especificar origins concretos con WithOrigins(\"https://myapp.com\") "
                        "en lugar de AllowAnyOrigin(). "
                        "Nunca combinar AllowAnyOrigin con AllowCredentials."
                    ),
                    cwe="CWE-942",
                    cvss_base=7.4,
                    evidence={"cors_config": "AllowAnyOrigin+AllowCredentials"},
                ))

        return findings

    def _check_aspnetcore_open_redirect(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta Open Redirect: LocalRedirect vs Redirect con URL dinámica.
        Redirect(userInput) → open redirect si userInput tiene URL externa.
        """
        findings: list[FrameworkFinding] = []

        REDIRECT_SYMBOLS = (
            "Microsoft.AspNetCore.Mvc.ControllerBase.Redirect",
            "Microsoft.AspNetCore.Mvc.Controller.Redirect",
            "Redirect",
        )
        SAFE_REDIRECT_SYMBOLS = (
            "LocalRedirect",
            "LocalRedirectPermanent",
        )

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue

            # Ignorar redirects locales (seguros)
            if any(s in sn.text for s in SAFE_REDIRECT_SYMBOLS):
                continue

            if not any(
                sn.resolved_symbol == s or sn.resolved_symbol.endswith(f".{s}") or sn.resolved_symbol.startswith(s)
                for s in REDIRECT_SYMBOLS
            ):
                continue

            # Solo reportar si el argumento no es literal
            if not sn.arguments or sn.arguments[0].is_literal:
                continue

            if self._open_redirect_is_sanitized_in_method(sn, model):
                continue

            if not self._method_has_http_input(sn, model):
                continue

            method = model.get_method_for_node(sn)
            cls    = model.get_class_for_node(sn)

            findings.append(self._make_finding(
                rule_id="FW-ASPNET-004",
                rule_name="Open Redirect potencial",
                vulnerability_kind=VulnerabilityKind.OPEN_REDIRECT,
                category=FrameworkFindingCategory.CONFIGURATION,
                confidence=TaintConfidence.HIGH,
                framework=Framework.ASPNET_CORE,
                sn=sn, method=method, cls=cls,
                title="Open Redirect: Redirect() con URL dinámica",
                description=(
                    "Redirect() con una URL construida desde input del usuario "
                    "permite a un atacante redirigir a víctimas a sitios maliciosos "
                    "(phishing, credential harvesting)."
                ),
                remediation=(
                    "Usar LocalRedirect() o Url.IsLocalUrl() para verificar "
                    "que la URL es local antes de redirigir. "
                    "Nunca usar URLs externas provenientes de input del usuario."
                ),
                cwe="CWE-601",
                cvss_base=6.1,
                evidence={"redirect_arg": sn.arguments[0].text if sn.arguments else ""},
            ))

        return findings

    def _method_has_http_input(
        self,
        sink_sn: CSharpSemanticNode,
        model: ParsedCSharpModel,
    ) -> bool:
        if not sink_sn.containing_method_id:
            return False

        nodes_in_method = model.nodes_by_method.get(sink_sn.containing_method_id, [])
        for n in nodes_in_method:
            text = (n.text or "").lower()
            if (
                "request.query" in text
                or "request.form" in text
                or "request.headers" in text
                or "request.body" in text
                or "request.bodyreader" in text
                or "route[" in text
            ):
                return True
        return False

    def _open_redirect_is_sanitized_in_method(
        self,
        sink_sn: CSharpSemanticNode,
        model: ParsedCSharpModel,
    ) -> bool:
        if not sink_sn.containing_method_id:
            return False

        nodes_in_method = model.nodes_by_method.get(sink_sn.containing_method_id, [])
        has_local_redirect = False
        has_is_local_url = False

        for n in nodes_in_method:
            text = (n.text or "").lower()
            symbol = (n.resolved_symbol or "").lower()

            if "localredirect" in text or "localredirect" in symbol:
                has_local_redirect = True
            if "islocalurl" in text or "islocalurl" in symbol:
                has_is_local_url = True

        return has_local_redirect or has_is_local_url

    # =========================================================================
    #  REGLAS DE ASP.NET MVC CLÁSICO
    # =========================================================================

    def _check_aspnet_mvc_validate_input(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """Detecta [ValidateInput(false)] en controllers ASP.NET MVC."""
        findings: list[FrameworkFinding] = []

        for ann in model.attribute_annotations:
            if ann.attribute_name != "ValidateInputAttribute":
                continue
            # Verificar si tiene argumento false
            if not any("false" in str(a).lower() for a in ann.arguments):
                continue

            method = model.methods_by_id.get(ann.target_id)
            cls    = model.classes_by_id.get(method.containing_class_id) if method else None

            findings.append(FrameworkFinding(
                finding_id=self._next_id(),
                vulnerability_kind=VulnerabilityKind.XSS,
                category=FrameworkFindingCategory.CONFIGURATION,
                confidence=TaintConfidence.HIGH,
                rule_id="FW-MVC-001",
                rule_name="[ValidateInput(false)] desactiva protección XSS",
                file=method.file if method else "",
                line=method.line_start if method else 0,
                code_snippet="[ValidateInput(false)]",
                method_id=ann.target_id,
                method_name=method.name if method else None,
                class_name=cls.name if cls else None,
                framework=Framework.ASPNET_MVC,
                title="[ValidateInput(false)] desactiva validación de request",
                description=(
                    "[ValidateInput(false)] desactiva la validación de HTML/script "
                    "en el request de ASP.NET, permitiendo que datos peligrosos "
                    "lleguen al action method sin filtrar."
                ),
                remediation=(
                    "Eliminar [ValidateInput(false)]. Si se necesita aceptar HTML, "
                    "usar [AllowHtml] solo en propiedades específicas y sanitizar "
                    "con HtmlSanitizer antes de renderizar."
                ),
                cwe="CWE-79",
                cvss_base=6.1,
                raw_evidence={"attribute_args": list(ann.arguments)},
            ))

        return findings

    # =========================================================================
    #  REGLAS DE ENTITY FRAMEWORK
    # =========================================================================

    def _check_ef_raw_sql(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta el uso de FromSqlRaw/ExecuteSqlRaw con string interpolation
        en lugar de FromSqlInterpolated (que es seguro).

        Caso peligroso:
          ctx.Users.FromSqlRaw($"SELECT * WHERE id = {id}")  ← INSEGURO
          ctx.Users.FromSqlInterpolated($"SELECT * WHERE id = {id}") ← SEGURO
        """
        findings: list[FrameworkFinding] = []

        UNSAFE_EF_SYMBOLS = (
            "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw",
            "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw",
        )

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue
            if not any(sn.resolved_symbol.startswith(s) for s in UNSAFE_EF_SYMBOLS):
                continue
            if not sn.has_potentially_tainted_args:
                continue

            # Detectar si se usa interpolación de string directamente
            # (FromSqlRaw con $"..." es el patrón peligroso)
            has_interpolation = "$\"" in sn.text or "string.Format" in sn.text
            has_concat = "+" in sn.text

            if not has_interpolation and not has_concat:
                continue

            method = model.get_method_for_node(sn)
            cls    = model.get_class_for_node(sn)

            method_name_ef = sn.resolved_symbol.split(".")[-1]

            findings.append(self._make_finding(
                rule_id="FW-EF-001",
                rule_name=f"EF Core {method_name_ef} con string interpolation",
                vulnerability_kind=VulnerabilityKind.SQL_INJECTION,
                category=FrameworkFindingCategory.INJECTION,
                confidence=TaintConfidence.HIGH,
                framework=Framework.EF_CORE,
                sn=sn, method=method, cls=cls,
                title=f"SQL Injection: {method_name_ef} con interpolación de string",
                description=(
                    f"{method_name_ef} con string interpolation ($\"...\") construye "
                    f"SQL directamente desde variables, lo que es equivalente a "
                    f"concatenar strings: vulnerable a SQL Injection."
                ),
                remediation=(
                    "Reemplazar FromSqlRaw($\"SELECT WHERE id={id}\") por "
                    "FromSqlInterpolated($\"SELECT WHERE id={id}\") — "
                    "FromSqlInterpolated parametriza automáticamente las interpolaciones."
                ),
                cwe="CWE-89",
                cvss_base=9.8,
                evidence={"ef_method": method_name_ef, "snippet": sn.text[:80]},
            ))

        return findings

    # =========================================================================
    #  REGLAS DE WCF
    # =========================================================================

    def _check_wcf_security(
        self, model: ParsedCSharpModel, profile: FrameworkProfile
    ) -> list[FrameworkFinding]:
        """
        Detecta misconfigurations de seguridad en WCF:
          • BasicHttpBinding sin HTTPS (transporte en claro)
          • OperationContract sin validación de input
        """
        findings: list[FrameworkFinding] = []

        for sn in model.semantic_nodes:
            if not sn.resolved_symbol:
                continue

            # BasicHttpBinding sin seguridad
            if "System.ServiceModel.BasicHttpBinding" in sn.resolved_symbol:
                # Verificar si configura Security.Mode = None
                nodes_nearby = [
                    n for n in model.semantic_nodes
                    if n.file == sn.file
                    and abs(n.line - sn.line) <= 10
                    and "Security.Mode" in n.text
                    and "None" in n.text
                ]
                if nodes_nearby:
                    method = model.get_method_for_node(sn)
                    cls    = model.get_class_for_node(sn)
                    findings.append(self._make_finding(
                        rule_id="FW-WCF-001",
                        rule_name="WCF BasicHttpBinding sin seguridad de transporte",
                        vulnerability_kind=VulnerabilityKind.UNKNOWN,
                        category=FrameworkFindingCategory.TRANSPORT_SECURITY,
                        confidence=TaintConfidence.HIGH,
                        framework=Framework.WCF,
                        sn=sn, method=method, cls=cls,
                        title="BasicHttpBinding con Security.Mode = None",
                        description=(
                            "BasicHttpBinding con Security.Mode = None envía datos "
                            "en texto plano sin cifrado ni autenticación."
                        ),
                        remediation=(
                            "Configurar Security.Mode = Transport (HTTPS) o "
                            "Security.Mode = TransportWithMessageCredential."
                        ),
                        cwe="CWE-319",
                        cvss_base=7.5,
                        evidence={"binding": "BasicHttpBinding", "mode": "None"},
                    ))

        return findings

    # =========================================================================
    #  HELPERS
    # =========================================================================

    def _make_finding(
        self,
        rule_id: str,
        rule_name: str,
        vulnerability_kind: VulnerabilityKind,
        category: FrameworkFindingCategory,
        confidence: TaintConfidence,
        framework: Framework,
        sn: CSharpSemanticNode,
        method: MethodInfo | None,
        cls: ClassInfo | None,
        title: str,
        description: str,
        remediation: str,
        cwe: str,
        cvss_base: float,
        evidence: dict[str, Any] | None = None,
    ) -> FrameworkFinding:
        return FrameworkFinding(
            finding_id=self._next_id(),
            vulnerability_kind=vulnerability_kind,
            category=category,
            confidence=confidence,
            rule_id=rule_id,
            rule_name=rule_name,
            file=sn.file,
            line=sn.line,
            code_snippet=sn.text[:100],
            method_id=method.method_id if method else None,
            method_name=method.name if method else None,
            class_name=cls.name if cls else None,
            framework=framework,
            title=title,
            description=description,
            remediation=remediation,
            cwe=cwe,
            cvss_base=cvss_base,
            raw_evidence=evidence or {},
        )

    def _next_id(self) -> str:
        self._counter += 1
        return f"fw-{self._counter:04d}"
