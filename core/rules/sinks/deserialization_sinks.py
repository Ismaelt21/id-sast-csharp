# =============================================================================
#  csharp-sast / core / rules / sinks / deserialization_sinks.py
# =============================================================================
#
#  CATÁLOGO DE SINKS DE INSECURE DESERIALIZATION PARA C#
#  ──────────────────────────────────────────────────────
#  Cubre: BinaryFormatter, SoapFormatter, NetDataContractSerializer,
#  JavaScriptSerializer, Newtonsoft.Json (con TypeNameHandling),
#  DataContractSerializer, YamlDotNet, MessagePack, LosFormatter.
#
#  SEVERIDAD:
#    always_vulnerable=True → CRITICAL (BinaryFormatter, SoapFormatter):
#    No existe forma segura de deserializar datos no confiables con estos.
#    always_vulnerable=False → depende del contexto y configuración.
#
# =============================================================================

from __future__ import annotations

DESERIALIZATION_SINKS: list[dict] = [

    # =========================================================================
    #  Formatters obsoletos (inherentemente inseguros)
    # =========================================================================
    {
        "id": "DESER-001", "rule_type": "sink",
        "symbol": "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",
        "name": "BinaryFormatter.Deserialize (inherentemente inseguro)",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": True,
        "confidence": "confirmed", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": (
            "BinaryFormatter.Deserialize es inherentemente inseguro. "
            "Permite deserializar grafos de objetos arbitrarios que pueden "
            "ejecutar código durante la deserialización (gadget chains). "
            "Obsoleto desde .NET 5, eliminado en .NET 9. "
            "No existe forma segura de usar BinaryFormatter con datos no confiables."
        ),
        "remediation": (
            "Eliminar BinaryFormatter del código. "
            "Reemplazar por System.Text.Json.JsonSerializer con tipos explícitos, "
            "MessagePack con resolvers restrictivos, "
            "o XmlSerializer con tipos conocidos."
        ),
        "safe_alternative": "System.Text.Json.JsonSerializer",
        "frameworks": ["generic", "aspnetcore", "aspnet_mvc"],
        "tags": ["deserialization", "rce", "critical", "deprecated", "owasp-a08"],
    },
    {
        "id": "DESER-002", "rule_type": "sink",
        "symbol": "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserialize",
        "name": "BinaryFormatter.UnsafeDeserialize",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": True,
        "confidence": "confirmed", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": "BinaryFormatter.UnsafeDeserialize — variante sin header check, igual de insegura.",
        "remediation": "Eliminar todo uso de BinaryFormatter. Sin excepción.",
        "safe_alternative": "System.Text.Json.JsonSerializer",
        "frameworks": ["generic"],
        "tags": ["deserialization", "rce", "critical", "deprecated"],
    },
    {
        "id": "DESER-003", "rule_type": "sink",
        "symbol": "System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize",
        "name": "SoapFormatter.Deserialize (inherentemente inseguro)",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": True,
        "confidence": "confirmed", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": (
            "SoapFormatter tiene las mismas vulnerabilidades que BinaryFormatter — "
            "deserialización de tipos arbitrarios → RCE. "
            "Eliminado en .NET Core."
        ),
        "remediation": "Reemplazar por DataContractSerializer con tipos explícitos en WCF.",
        "safe_alternative": "System.Runtime.Serialization.DataContractSerializer",
        "frameworks": ["generic", "wcf"],
        "tags": ["deserialization", "rce", "critical", "deprecated"],
    },
    {
        "id": "DESER-004", "rule_type": "sink",
        "symbol": "System.Runtime.Serialization.NetDataContractSerializer.Deserialize",
        "name": "NetDataContractSerializer.Deserialize",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": True,
        "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": (
            "NetDataContractSerializer serializa info de tipos .NET embebida en el payload, "
            "permitiendo gadget chains. Eliminado en .NET Core."
        ),
        "remediation": "Usar DataContractSerializer con tipos conocidos y sin TypeResolver.",
        "safe_alternative": "System.Runtime.Serialization.DataContractSerializer",
        "frameworks": ["generic", "wcf"],
        "tags": ["deserialization", "rce"],
    },

    # =========================================================================
    #  ASP.NET LosFormatter
    # =========================================================================
    {
        "id": "DESER-005", "rule_type": "sink",
        "symbol": "System.Web.UI.LosFormatter.Deserialize",
        "name": "LosFormatter.Deserialize (ViewState deserialization)",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": (
            "LosFormatter se usa para deserializar ViewState en ASP.NET WebForms. "
            "Si el ViewState MAC está deshabilitado o el MachineKey está comprometido, "
            "un atacante puede forjar ViewState malicioso → RCE."
        ),
        "remediation": (
            "Habilitar EnableViewStateMac=true y ViewStateEncryptionMode=Always. "
            "Usar un MachineKey fuerte y rotarlo periódicamente. "
            "En .NET Framework 4.5+: usar el framework de validación de ViewState mejorado."
        ),
        "safe_alternative": "ViewState con MAC habilitado y encryption",
        "frameworks": ["aspnet_mvc"],
        "tags": ["deserialization", "viewstate", "webforms", "rce"],
    },

    # =========================================================================
    #  JavaScriptSerializer (ASP.NET MVC clásico)
    # =========================================================================
    {
        "id": "DESER-006", "rule_type": "sink",
        "symbol": "System.Web.Script.Serialization.JavaScriptSerializer.Deserialize",
        "name": "JavaScriptSerializer.Deserialize con TypeResolver",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": (
            "JavaScriptSerializer con SimpleTypeResolver puede deserializar "
            "tipos arbitrarios — vector conocido de RCE en aplicaciones ASP.NET MVC. "
            "CVE-2017-9248 y variantes explotan esta clase."
        ),
        "remediation": "Usar System.Text.Json.JsonSerializer. No usar SimpleTypeResolver.",
        "safe_alternative": "System.Text.Json.JsonSerializer",
        "frameworks": ["aspnet_mvc"],
        "tags": ["deserialization", "rce", "aspnet"],
    },
    {
        "id": "DESER-007", "rule_type": "sink",
        "symbol": "System.Web.Script.Serialization.JavaScriptSerializer.DeserializeObject",
        "name": "JavaScriptSerializer.DeserializeObject",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-502", "cvss_base": 8.1,
        "description": "DeserializeObject retorna object — potencialmente peligroso si el resolver está configurado.",
        "remediation": "Usar System.Text.Json.JsonSerializer con tipo explícito.",
        "safe_alternative": "System.Text.Json.JsonSerializer",
        "frameworks": ["aspnet_mvc"],
        "tags": ["deserialization", "aspnet"],
    },

    # =========================================================================
    #  Newtonsoft.Json
    # =========================================================================
    {
        "id": "DESER-008", "rule_type": "sink",
        "symbol": "Newtonsoft.Json.JsonConvert.DeserializeObject",
        "name": "JsonConvert.DeserializeObject con TypeNameHandling",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-502", "cvss_base": 8.1,
        "description": (
            "Newtonsoft.Json con TypeNameHandling != None puede deserializar "
            "tipos arbitrarios mediante el campo '$type' en el JSON. "
            "Si los datos vienen de fuente no confiable → RCE. "
            "Solo vulnerable cuando TypeNameHandling no es None."
        ),
        "remediation": (
            "Asegurar TypeNameHandling = TypeNameHandling.None (default). "
            "Si se necesita polimorfismo, usar [JsonDerivedType] de System.Text.Json "
            "o JsonConverter con whitelist de tipos permitidos."
        ),
        "safe_alternative": "Newtonsoft.Json con TypeNameHandling.None o System.Text.Json",
        "frameworks": ["generic", "aspnetcore"],
        "tags": ["deserialization", "json", "newtonsoft"],
    },
    {
        "id": "DESER-009", "rule_type": "sink",
        "symbol": "Newtonsoft.Json.JsonSerializer.Deserialize",
        "name": "JsonSerializer.Deserialize (Newtonsoft) con TypeNameHandling",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-502", "cvss_base": 8.1,
        "description": "JsonSerializer.Deserialize de Newtonsoft — mismo riesgo que JsonConvert.DeserializeObject.",
        "remediation": "Verificar que el JsonSerializerSettings no tenga TypeNameHandling != None.",
        "safe_alternative": "System.Text.Json.JsonSerializer",
        "frameworks": ["generic"],
        "tags": ["deserialization", "json", "newtonsoft"],
    },

    # =========================================================================
    #  DataContractSerializer
    # =========================================================================
    {
        "id": "DESER-010", "rule_type": "sink",
        "symbol": "System.Runtime.Serialization.DataContractSerializer.ReadObject",
        "name": "DataContractSerializer.ReadObject con datos externos",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "medium", "severity": "MEDIUM",
        "cwe": "CWE-502", "cvss_base": 6.5,
        "description": (
            "DataContractSerializer es generalmente seguro con tipos conocidos, "
            "pero si se usa DataContractResolver o knownTypes mal configurados, "
            "puede deserializar tipos inesperados."
        ),
        "remediation": (
            "Especificar explícitamente los knownTypes permitidos. "
            "No usar DataContractResolver con datos externos."
        ),
        "safe_alternative": "DataContractSerializer con knownTypes explícitos",
        "frameworks": ["wcf", "generic"],
        "tags": ["deserialization", "wcf"],
    },

    # =========================================================================
    #  YamlDotNet
    # =========================================================================
    {
        "id": "DESER-011", "rule_type": "sink",
        "symbol": "YamlDotNet.Serialization.Deserializer.Deserialize",
        "name": "YamlDotNet Deserialize con datos externos",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-502", "cvss_base": 8.1,
        "description": (
            "YamlDotNet puede deserializar tipos arbitrarios con la directiva !!type "
            "si no se usa un deserializador con tipos restringidos."
        ),
        "remediation": (
            "Usar DeserializerBuilder().WithTagMapping() para limitar tipos. "
            "O usar YamlDotNet en modo StaticContext para tipos solo conocidos."
        ),
        "safe_alternative": "YamlDotNet con StaticContext o tipos restringidos",
        "frameworks": ["generic"],
        "tags": ["deserialization", "yaml"],
    },
    {
        "id": "DESER-012", "rule_type": "sink",
        "symbol": "YamlDotNet.Serialization.DeserializerBuilder.Build",
        "name": "YamlDotNet DeserializerBuilder sin restricción de tipos",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "low", "severity": "MEDIUM",
        "cwe": "CWE-502", "cvss_base": 5.9,
        "description": "YamlDotNet DeserializerBuilder sin WithTagMapping() o type restriction puede ser explotado.",
        "remediation": "Usar WithTagMapping o StaticContext.",
        "safe_alternative": "YamlDotNet con tipos restringidos",
        "frameworks": ["generic"],
        "tags": ["deserialization", "yaml", "builder"],
    },

    # =========================================================================
    #  MessagePack
    # =========================================================================
    {
        "id": "DESER-013", "rule_type": "sink",
        "symbol": "MessagePack.MessagePackSerializer.Deserialize",
        "name": "MessagePack Deserialize con TypelessContractlessResolver",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-502", "cvss_base": 8.1,
        "description": (
            "MessagePack con TypelessContractlessStandardResolver permite "
            "deserializar tipos arbitrarios embebidos en el payload binario."
        ),
        "remediation": "Usar StandardResolver con tipos conocidos. Nunca TypelessContractlessStandardResolver con datos externos.",
        "safe_alternative": "MessagePack con StandardResolver restrictivo",
        "frameworks": ["generic"],
        "tags": ["deserialization", "messagepack"],
    },

    # =========================================================================
    #  ObjectStateFormatter
    # =========================================================================
    {
        "id": "DESER-014", "rule_type": "sink",
        "symbol": "System.Web.UI.ObjectStateFormatter.Deserialize",
        "name": "ObjectStateFormatter.Deserialize",
        "vulnerability": "INSECURE_DESERIALIZATION", "tainted_args": [0],
        "always_vulnerable": False,
        "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-502", "cvss_base": 9.8,
        "description": (
            "ObjectStateFormatter usa BinaryFormatter internamente. "
            "Si los datos provienen de cliente sin MAC verification → RCE."
        ),
        "remediation": "Nunca deserializar ObjectStateFormatter con datos del cliente sin MAC validation.",
        "safe_alternative": "ViewState con MAC habilitado",
        "frameworks": ["aspnet_mvc"],
        "tags": ["deserialization", "viewstate", "rce"],
    },
]


def get_deserialization_sink_rules() -> list[dict]:
    """Retorna el catálogo completo de reglas de Insecure Deserialization."""
    return DESERIALIZATION_SINKS


def get_deserialization_sink_symbols() -> set[str]:
    return {rule["symbol"] for rule in DESERIALIZATION_SINKS}


def get_always_vulnerable_deserialization_sinks() -> list[dict]:
    """Retorna los sinks que son siempre vulnerables (BinaryFormatter, SoapFormatter)."""
    return [r for r in DESERIALIZATION_SINKS if r.get("always_vulnerable", False)]


def get_deserialization_sinks_by_framework(framework: str) -> list[dict]:
    return [r for r in DESERIALIZATION_SINKS if framework in r.get("frameworks", [])]