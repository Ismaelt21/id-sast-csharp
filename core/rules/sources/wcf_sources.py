# =============================================================================
#  csharp-sast / core / rules / sources / wcf_sources.py
# =============================================================================
#
#  FUENTES DE INPUT DEL ATACANTE EN WCF (Windows Communication Foundation)
#  ──────────────────────────────────────────────────────────────────────────
#
#  QUÉ ES WCF:
#    Windows Communication Foundation es el framework de servicios SOAP/REST
#    de .NET Framework. Aunque obsoleto en .NET Core (reemplazado por gRPC
#    y HTTP APIs), sigue siendo muy común en aplicaciones enterprise legacy.
#    CoreWCF es el port para .NET moderno.
#
#  MODELO DE TAINT EN WCF:
#    A diferencia de ASP.NET donde los parámetros llegan via HTTP request,
#    en WCF los datos llegan via:
#      1. Parámetros de métodos [OperationContract] (model binding automático)
#      2. Acceso directo al OperationContext (headers SOAP, mensaje crudo)
#      3. MessageInspectors (interceptores del pipeline)
#      4. IParameterInspector (inspección de parámetros)
#
#  FUENTES IMPLÍCITAS:
#    Los parámetros de métodos [OperationContract] son automáticamente tainted
#    igual que los action methods de ASP.NET — el taint_analyzer los detecta
#    por el atributo [OperationContractAttribute].
#    Este catálogo cubre el acceso DIRECTO al contexto WCF.
#
#  PARTICULARIDADES DE SEGURIDAD WCF:
#    • SOAP headers personalizados son controlables por el cliente
#    • El cuerpo SOAP se deserializa automáticamente — si DataContract
#      tiene tipos incorrectos → Insecure Deserialization
#    • BasicHttpBinding sin seguridad de transporte → datos en claro
#    • NetTcpBinding puede exponer puertos internos si mal configurado
#    • REST sobre WCF (WebHttpBinding) tiene los mismos riesgos que HTTP REST
#
#  LABELS DE TAINT:
#    USER_INPUT    → cliente del servicio WCF controla el dato
#    EXTERNAL_INPUT → dato viene de un sistema externo via WCF
#
# =============================================================================

from __future__ import annotations

WCF_SOURCES: list[dict] = [

    # =========================================================================
    #  OperationContext — contexto de la operación WCF en ejecución
    # =========================================================================

    {
        "id":                    "SRC-WCF-001",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.OperationContext",
        "name":                  "WCF OperationContext (contexto completo de la operación)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "OperationContext.Current contiene toda la información de la operación WCF "
            "en ejecución: mensaje entrante, headers SOAP, datos del cliente. "
            "Si se accede a propiedades del mensaje o headers → datos del cliente "
            "completamente tainted. "
            "Disponible via OperationContext.Current (static accessor)."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "service", "context", "soap", "user-input"],
    },
    {
        "id":                    "SRC-WCF-002",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.OperationContext.IncomingMessageHeaders",
        "name":                  "WCF IncomingMessageHeaders (SOAP headers del cliente)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Headers SOAP del mensaje entrante. Controlados por el cliente del servicio. "
            "Severity_multiplier 0.9 — menos explorados que el body, "
            "pero son una fuente de taint via header injection en logs o SQL."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "soap", "headers", "user-input"],
    },
    {
        "id":                    "SRC-WCF-003",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.OperationContext.IncomingMessageProperties",
        "name":                  "WCF IncomingMessageProperties",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Propiedades del mensaje WCF entrante. Incluye información de transporte "
            "como RemoteEndpointMessageProperty (IP del cliente). "
            "Si se usa RemoteEndpoint.Address en logs o queries → tainted "
            "(IP puede ser spoofed en ciertos escenarios)."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "message", "properties", "transport"],
    },
    {
        "id":                    "SRC-WCF-004",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.OperationContext.RequestContext",
        "name":                  "WCF RequestContext (mensaje de request crudo)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "RequestContext contiene el mensaje WCF completo de la request. "
            "Si se accede a RequestMessage para parsear manualmente → tainted."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "request", "message", "raw"],
    },

    # =========================================================================
    #  Message — mensaje SOAP crudo
    # =========================================================================

    {
        "id":                    "SRC-WCF-005",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Channels.Message",
        "name":                  "WCF Message (mensaje SOAP crudo)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Objeto Message de WCF — el mensaje SOAP crudo. "
            "Severity_multiplier 1.1 porque el body SOAP puede contener XML arbitrario "
            "que si se parsea manualmente puede resultar en XXE o Injection. "
            "Incluye: headers, body, properties."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "message", "soap", "xml", "user-input"],
    },
    {
        "id":                    "SRC-WCF-006",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Channels.MessageHeaders",
        "name":                  "WCF MessageHeaders (headers del mensaje SOAP)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Headers del mensaje SOAP. Controlados por el cliente WCF. "
            "Si se lee un header custom y se usa en código sensible → tainted."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "soap", "headers"],
    },
    {
        "id":                    "SRC-WCF-007",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Channels.MessageBuffer.CreateMessage",
        "name":                  "WCF MessageBuffer.CreateMessage (copia del mensaje)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "MessageBuffer almacena una copia del mensaje WCF para procesamiento múltiple. "
            "El mensaje creado desde el buffer contiene datos del cliente."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "message", "buffer"],
    },

    # =========================================================================
    #  WebOperationContext — WCF con binding HTTP (REST over WCF)
    # =========================================================================

    {
        "id":                    "SRC-WCF-008",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Web.WebOperationContext",
        "name":                  "WCF WebOperationContext (REST over WCF)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Contexto de operación WCF REST (WebHttpBinding). "
            "WebOperationContext.Current.IncomingRequest contiene "
            "los parámetros HTTP de la petición REST. "
            "Tiene los mismos riesgos que las sources HTTP de ASP.NET MVC."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "rest", "http", "webhttp", "user-input"],
    },
    {
        "id":                    "SRC-WCF-009",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Web.IncomingWebRequestContext",
        "name":                  "WCF IncomingWebRequestContext (HTTP request en WCF REST)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "IncomingWebRequestContext expone los datos HTTP en WCF REST: "
            "headers, query string, URL, content-type. "
            "Todos controlados por el cliente HTTP."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "rest", "http", "request"],
    },
    {
        "id":                    "SRC-WCF-010",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Web.IncomingWebRequestContext.UriTemplateMatch",
        "name":                  "WCF UriTemplateMatch (parámetros de URL REST)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "UriTemplateMatch contiene los parámetros extraídos del URI template "
            "en WCF REST. Equivalente a RouteData.Values en ASP.NET Core."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "rest", "url", "route"],
    },

    # =========================================================================
    #  Pipeline de WCF — interceptores y behaviors
    # =========================================================================

    {
        "id":                    "SRC-WCF-011",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Dispatcher.IParameterInspector",
        "name":                  "WCF IParameterInspector.BeforeCall (parámetros interceptados)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Los parámetros interceptados por IParameterInspector.BeforeCall "
            "vienen del cliente WCF y son tainted. "
            "Si un inspector registra o procesa parámetros → los datos son del cliente."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "pipeline", "inspector", "parameters"],
    },
    {
        "id":                    "SRC-WCF-012",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Dispatcher.IMessageInspector",
        "name":                  "WCF IMessageInspector.AfterReceiveRequest (mensaje interceptado)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "IMessageInspector intercepta mensajes antes de que lleguen al servicio. "
            "AfterReceiveRequest recibe el mensaje crudo del cliente — tainted. "
            "Severity_multiplier 1.1 porque intercepta antes de la deserialización, "
            "acceso al XML SOAP crudo → riesgo de XXE si se parsea."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "pipeline", "inspector", "message"],
    },
    {
        "id":                    "SRC-WCF-013",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.Dispatcher.EndpointDispatcher",
        "name":                  "WCF EndpointDispatcher (datos del endpoint)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "EndpointDispatcher gestiona el despacho de mensajes a las operaciones. "
            "Los datos que fluyen por él son del cliente WCF — tainted si se accede directamente."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "dispatcher", "endpoint"],
    },

    # =========================================================================
    #  CoreWCF — port de WCF para .NET moderno
    # =========================================================================

    {
        "id":                    "SRC-WCF-014",
        "rule_type":             "source",
        "symbol":                "CoreWCF.OperationContext",
        "name":                  "CoreWCF OperationContext",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "CoreWCF (port de WCF para .NET 6+) OperationContext. "
            "Mismo comportamiento que System.ServiceModel.OperationContext — "
            "datos del cliente completamente tainted."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "corewcf", "dotnetcore", "context"],
    },
    {
        "id":                    "SRC-WCF-015",
        "rule_type":             "source",
        "symbol":                "CoreWCF.Channels.Message",
        "name":                  "CoreWCF Message",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "CoreWCF Message — equivalente a System.ServiceModel.Channels.Message "
            "en el port para .NET moderno. Mismo riesgo."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "corewcf", "message", "soap"],
    },

    # =========================================================================
    #  WCF Security — datos de seguridad del mensaje
    # =========================================================================

    {
        "id":                    "SRC-WCF-016",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.ServiceSecurityContext",
        "name":                  "WCF ServiceSecurityContext (identidad del cliente)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "authenticated",
        "description": (
            "ServiceSecurityContext contiene la identidad del cliente autenticado. "
            "PrimaryIdentity.Name, Claims, etc. son del cliente. "
            "Severity_multiplier 0.7 — requiere autenticación, pero si se usa "
            "el nombre de usuario en queries o logs → tainted."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "security", "identity", "authenticated"],
    },
    {
        "id":                    "SRC-WCF-017",
        "rule_type":             "source",
        "symbol":                "System.ServiceModel.ServiceSecurityContext.PrimaryIdentity",
        "name":                  "WCF PrimaryIdentity.Name (nombre del cliente autenticado)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "authenticated",
        "description": (
            "Nombre de la identidad primaria del cliente WCF. "
            "Si se usa en queries SQL o logs → tainted aunque requiera autenticación."
        ),
        "frameworks":            ["wcf"],
        "tags":                  ["wcf", "security", "identity", "name"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCIONES DE ACCESO AL CATÁLOGO
# ─────────────────────────────────────────────────────────────────────────────

def get_wcf_source_rules() -> list[dict]:
    """Retorna el catálogo completo de sources WCF."""
    return WCF_SOURCES


def get_wcf_source_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in WCF_SOURCES}


def get_wcf_rest_sources() -> list[dict]:
    """Retorna sources específicas de WCF REST (WebHttpBinding)."""
    return [r for r in WCF_SOURCES if "rest" in r.get("tags", [])]


def get_wcf_soap_sources() -> list[dict]:
    """Retorna sources específicas de WCF SOAP."""
    return [r for r in WCF_SOURCES if "soap" in r.get("tags", [])]


def get_wcf_pipeline_sources() -> list[dict]:
    """Retorna sources del pipeline WCF (interceptores y behaviors)."""
    return [r for r in WCF_SOURCES if "pipeline" in r.get("tags", [])]


def get_source_taint_labels() -> dict[str, str]:
    """Retorna mapa {symbol_prefix: taint_label} para el TaintAnalyzer."""
    return {rule["symbol"]: rule["taint_label"] for rule in WCF_SOURCES}


def get_source_severity_multipliers() -> dict[str, float]:
    """Retorna mapa {symbol_prefix: severity_multiplier} para el VulnerabilityClassifier."""
    return {
        rule["symbol"]: rule.get("severity_multiplier", 1.0)
        for rule in WCF_SOURCES
    }