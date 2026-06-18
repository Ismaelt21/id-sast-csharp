# =============================================================================
#  csharp-sast / core / rules / sinks / ssrf_sinks.py
# =============================================================================
#
#  CATÁLOGO DE SINKS DE SERVER-SIDE REQUEST FORGERY (SSRF) PARA C#
#  ─────────────────────────────────────────────────────────────────
#  Cubre: System.Net.Http.HttpClient, WebClient, WebRequest,
#  RestSharp, Flurl.Http, Refit, HttpWebRequest, SocketsHttpHandler,
#  y clientes de SDKs cloud (AWS, Azure).
#
#  QUÉ ES SSRF EN .NET:
#    El atacante controla la URL destino de una petición HTTP saliente
#    que el servidor realiza en nombre suyo. Puede usarse para:
#      • Acceder a metadata de cloud (169.254.169.254 en AWS/Azure/GCP)
#      • Acceder a servicios internos no expuestos públicamente
#      • Escanear la red interna del servidor
#      • Bypassear firewalls y controles de acceso
#      • En algunos casos: SSRF → RCE via servicios internos vulnerables
#
#  CONTEXTO DE RIESGO AUMENTADO:
#    En entornos cloud (AWS, Azure, GCP) el endpoint de metadata
#    (169.254.169.254) puede exponer credenciales temporales de IAM
#    con un solo request: GET http://169.254.169.254/latest/meta-data/
#    Esto hace de SSRF una vulnerabilidad CRÍTICA en cloud.
#
#  ESTRUCTURA DEL CATÁLOGO:
#    Alineada con sql_sinks.py, command_sinks.py, xml_sinks.py,
#    deserialization_sinks.py — mismos campos, misma convención.
#
# =============================================================================

from __future__ import annotations

SSRF_SINKS: list[dict] = [

    # =========================================================================
    #  System.Net.Http.HttpClient — cliente HTTP moderno de .NET
    #  El más usado en aplicaciones ASP.NET Core modernas.
    # =========================================================================

    {
        "id":              "SSRF-001",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.GetAsync",
        "name":            "HttpClient.GetAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description": (
            "HttpClient.GetAsync con URL controlada por el usuario permite SSRF. "
            "En entornos cloud expone el endpoint de metadata (169.254.169.254) "
            "que puede retornar credenciales IAM. "
            "También permite acceder a servicios internos no expuestos públicamente."
        ),
        "remediation": (
            "Validar el host de la URL contra una whitelist de dominios permitidos. "
            "Extraer el host con new Uri(url).Host y comparar contra la whitelist. "
            "Bloquear explícitamente IPs privadas: 127.0.0.1, 10.x.x.x, "
            "172.16-31.x.x, 192.168.x.x, 169.254.x.x (metadata cloud). "
            "Deshabilitar redirecciones: new HttpClientHandler { AllowAutoRedirect = false }."
        ),
        "safe_alternative": "HttpClient con validación de host contra whitelist",
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["ssrf", "http", "cloud", "injection", "owasp-a10"],
    },
    {
        "id":              "SSRF-002",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.PostAsync",
        "name":            "HttpClient.PostAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description": (
            "HttpClient.PostAsync con URL dinámica. "
            "Permite SSRF con datos POST a servicios internos o al endpoint de metadata cloud."
        ),
        "remediation": (
            "Whitelist de dominios permitidos. "
            "Deshabilitar redirecciones automáticas. "
            "Validar que el protocolo sea https:// (bloquear http://, ftp://, file://)."
        ),
        "safe_alternative": "HttpClient con validación de URI antes de la llamada",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "post"],
    },
    {
        "id":              "SSRF-003",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.PutAsync",
        "name":            "HttpClient.PutAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "HttpClient.PutAsync con URL dinámica — mismo riesgo de SSRF que GetAsync/PostAsync.",
        "remediation":     "Whitelist de dominios. Bloquear IPs privadas y cloud metadata.",
        "safe_alternative": "HttpClient con validación de URI",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "put"],
    },
    {
        "id":              "SSRF-004",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.DeleteAsync",
        "name":            "HttpClient.DeleteAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "HttpClient.DeleteAsync con URL dinámica.",
        "remediation":     "Whitelist de dominios. Bloquear IPs privadas.",
        "safe_alternative": "HttpClient con validación de URI",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "delete"],
    },
    {
        "id":              "SSRF-005",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.SendAsync",
        "name":            "HttpClient.SendAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description": (
            "HttpClient.SendAsync acepta un HttpRequestMessage completo. "
            "Si la URL del mensaje proviene del usuario → SSRF con cualquier HTTP method."
        ),
        "remediation":     "Validar el URI del HttpRequestMessage antes de enviarlo.",
        "safe_alternative": "HttpClient con validación del HttpRequestMessage.RequestUri",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "send"],
    },
    {
        "id":              "SSRF-006",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.GetStringAsync",
        "name":            "HttpClient.GetStringAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "Shorthand de GetAsync que retorna string directamente — mismo riesgo de SSRF.",
        "remediation":     "Whitelist de dominios. Bloquear IPs privadas.",
        "safe_alternative": "HttpClient con validación de URI",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http"],
    },
    {
        "id":              "SSRF-007",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.GetByteArrayAsync",
        "name":            "HttpClient.GetByteArrayAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "HttpClient.GetByteArrayAsync descarga contenido binario desde URL dinámica — riesgo SSRF.",
        "remediation":     "Whitelist de dominios permitidos.",
        "safe_alternative": "HttpClient con validación de URI",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "binary"],
    },
    {
        "id":              "SSRF-008",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.HttpClient.GetStreamAsync",
        "name":            "HttpClient.GetStreamAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "HttpClient.GetStreamAsync retorna un stream desde URL dinámica — riesgo SSRF.",
        "remediation":     "Whitelist de dominios permitidos.",
        "safe_alternative": "HttpClient con validación de URI",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "stream"],
    },

    # =========================================================================
    #  System.Net.WebClient — obsoleto pero aún común en código legacy
    # =========================================================================

    {
        "id":              "SSRF-009",
        "rule_type":       "sink",
        "symbol":          "System.Net.WebClient.DownloadString",
        "name":            "WebClient.DownloadString con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description": (
            "WebClient (obsoleto en .NET 6+) con URL dinámica. "
            "Además del riesgo de SSRF, WebClient no soporta async moderno "
            "y tiene peor gestión de errores que HttpClient."
        ),
        "remediation":     "Migrar a HttpClient con validación de URL.",
        "safe_alternative": "System.Net.Http.HttpClient con validación",
        "frameworks":      ["generic", "aspnet_mvc"],
        "tags":            ["ssrf", "http", "deprecated", "webclient"],
    },
    {
        "id":              "SSRF-010",
        "rule_type":       "sink",
        "symbol":          "System.Net.WebClient.DownloadData",
        "name":            "WebClient.DownloadData con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "WebClient.DownloadData descarga bytes desde URL dinámica — riesgo SSRF.",
        "remediation":     "Migrar a HttpClient.GetByteArrayAsync con validación de URL.",
        "safe_alternative": "System.Net.Http.HttpClient con validación",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "http", "deprecated"],
    },
    {
        "id":              "SSRF-011",
        "rule_type":       "sink",
        "symbol":          "System.Net.WebClient.DownloadFile",
        "name":            "WebClient.DownloadFile con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "WebClient.DownloadFile descarga un archivo desde URL dinámica — riesgo SSRF y path traversal combinados.",
        "remediation":     "Migrar a HttpClient con validación de URL y Path.GetFileName para el nombre del archivo.",
        "safe_alternative": "HttpClient con validación + Path.GetFileName",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "http", "deprecated", "path"],
    },
    {
        "id":              "SSRF-012",
        "rule_type":       "sink",
        "symbol":          "System.Net.WebClient.UploadString",
        "name":            "WebClient.UploadString con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "WebClient.UploadString envía datos POST a URL dinámica — SSRF con body controlado.",
        "remediation":     "Migrar a HttpClient.PostAsync con validación de URL.",
        "safe_alternative": "HttpClient.PostAsync con validación",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "http", "deprecated"],
    },
    {
        "id":              "SSRF-013",
        "rule_type":       "sink",
        "symbol":          "System.Net.WebClient.OpenRead",
        "name":            "WebClient.OpenRead con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "WebClient.OpenRead retorna stream desde URL dinámica — riesgo SSRF.",
        "remediation":     "Migrar a HttpClient.GetStreamAsync con validación.",
        "safe_alternative": "HttpClient.GetStreamAsync con validación",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "http", "deprecated"],
    },

    # =========================================================================
    #  System.Net.WebRequest / HttpWebRequest — obsoleto pero común en legacy
    # =========================================================================

    {
        "id":              "SSRF-014",
        "rule_type":       "sink",
        "symbol":          "System.Net.WebRequest.Create",
        "name":            "WebRequest.Create con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description": (
            "WebRequest.Create (obsoleto) con URL dinámica. "
            "Soporta múltiples protocolos (http, https, ftp, file) — "
            "el protocolo file:// permite leer archivos del servidor directamente."
        ),
        "remediation": (
            "Migrar a HttpClient. "
            "Si se mantiene WebRequest, rechazar URLs con protocolo distinto a https://."
        ),
        "safe_alternative": "System.Net.Http.HttpClient con validación de URI",
        "frameworks":      ["generic", "aspnet_mvc"],
        "tags":            ["ssrf", "http", "deprecated", "file-protocol"],
    },
    {
        "id":              "SSRF-015",
        "rule_type":       "sink",
        "symbol":          "System.Net.HttpWebRequest..ctor",
        "name":            "HttpWebRequest con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "HttpWebRequest construido con URL dinámica — riesgo SSRF.",
        "remediation":     "Migrar a HttpClient con validación de URI.",
        "safe_alternative": "HttpClient con validación",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "http", "deprecated"],
    },

    # =========================================================================
    #  RestSharp — librería HTTP popular para .NET
    # =========================================================================

    {
        "id":              "SSRF-016",
        "rule_type":       "sink",
        "symbol":          "RestSharp.RestClient..ctor",
        "name":            "RestSharp RestClient con URL base dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description": (
            "RestSharp RestClient construido con URL base controlada por el usuario. "
            "Si el usuario elige el servidor destino → SSRF. "
            "La URL base define el servidor; todos los requests van a ese servidor."
        ),
        "remediation": (
            "Hardcodear la URL base del RestClient en la configuración. "
            "Nunca construirla desde input del usuario. "
            "Si es necesario múltiples endpoints, usar una whitelist de URLs permitidas."
        ),
        "safe_alternative": "RestClient con base URL fija desde configuración",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "restsharp"],
    },
    {
        "id":              "SSRF-017",
        "rule_type":       "sink",
        "symbol":          "RestSharp.RestClient.ExecuteAsync",
        "name":            "RestSharp ExecuteAsync con URL de request dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "RestSharp ExecuteAsync — si el RestRequest tiene URL dinámica, el SSRF aplica al request.",
        "remediation":     "Construir RestRequest con recursos relativos, no URLs absolutas del usuario.",
        "safe_alternative": "RestRequest con recurso relativo fijo",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "restsharp"],
    },
    {
        "id":              "SSRF-018",
        "rule_type":       "sink",
        "symbol":          "RestSharp.RestClient.GetAsync",
        "name":            "RestSharp RestClient.GetAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "RestSharp GetAsync shorthand con URL dinámica.",
        "remediation":     "Hardcodear el endpoint. Usar parámetros de query validados.",
        "safe_alternative": "RestClient con base URL fija + recursos relativos",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "restsharp"],
    },

    # =========================================================================
    #  Flurl.Http — librería fluent HTTP popular
    # =========================================================================

    {
        "id":              "SSRF-019",
        "rule_type":       "sink",
        "symbol":          "Flurl.Http.FlurlClient..ctor",
        "name":            "Flurl FlurlClient con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "Flurl.Http FlurlClient con URL base controlada por el usuario — riesgo SSRF.",
        "remediation":     "Hardcodear la URL base. Usar configuración de la aplicación para endpoints.",
        "safe_alternative": "FlurlClient con URL base desde configuración",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["ssrf", "http", "flurl"],
    },
    {
        "id":              "SSRF-020",
        "rule_type":       "sink",
        "symbol":          "Flurl.Http.FlurlRequest.GetAsync",
        "name":            "Flurl GetAsync con URL dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       8.6,
        "description":     "Flurl GetAsync con URL construida dinámicamente desde input del usuario.",
        "remediation":     "Validar el host de la URL contra whitelist antes de hacer el request.",
        "safe_alternative": "Flurl con URL base fija + segmentos validados",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "flurl"],
    },

    # =========================================================================
    #  System.Net.Http.SocketsHttpHandler — handler de bajo nivel
    # =========================================================================

    {
        "id":              "SSRF-021",
        "rule_type":       "sink",
        "symbol":          "System.Net.Http.SocketsHttpHandler",
        "name":            "SocketsHttpHandler con ConnectCallback dinámico",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "MEDIUM",
        "cwe":             "CWE-918",
        "cvss_base":       6.5,
        "description": (
            "SocketsHttpHandler es el handler de bajo nivel de HttpClient. "
            "Si ConnectCallback usa hosts o puertos dinámicos del usuario "
            "puede resultar en SSRF de bajo nivel."
        ),
        "remediation":     "No usar datos del usuario en ConnectCallback. Hardcodear hosts en el handler.",
        "safe_alternative": "HttpClient sin ConnectCallback dinámico",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "http", "low-level"],
    },

    # =========================================================================
    #  SDKs de cloud — riesgo especial por acceso a metadata
    # =========================================================================

    {
        "id":              "SSRF-022",
        "rule_type":       "sink",
        "symbol":          "Amazon.S3.AmazonS3Client..ctor",
        "name":            "AWS SDK S3Client con endpoint dinámico",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "MEDIUM",
        "cwe":             "CWE-918",
        "cvss_base":       6.5,
        "description": (
            "Amazon S3 Client construido con ServiceURL dinámica puede "
            "apuntar a servicios internos o a endpoints maliciosos. "
            "Menor riesgo que HttpClient pero potencialmente explotable."
        ),
        "remediation": (
            "Usar el endpoint de AWS regional por defecto (no sobreescribir ServiceURL). "
            "Si es necesario sobreescribir, validar que el endpoint sea de AWS."
        ),
        "safe_alternative": "AmazonS3Client con configuración default de región",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "aws", "cloud", "s3"],
    },
    {
        "id":              "SSRF-023",
        "rule_type":       "sink",
        "symbol":          "Azure.Storage.Blobs.BlobServiceClient..ctor",
        "name":            "Azure BlobServiceClient con connection string dinámico",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "MEDIUM",
        "cwe":             "CWE-918",
        "cvss_base":       6.5,
        "description": (
            "BlobServiceClient con connection string o URI dinámico puede "
            "ser dirigido a cuentas de storage arbitrarias."
        ),
        "remediation": (
            "Cargar la connection string desde appsettings o KeyVault. "
            "Nunca construirla desde input del usuario."
        ),
        "safe_alternative": "BlobServiceClient con URI desde configuración",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "azure", "cloud", "blob"],
    },

    # =========================================================================
    #  System.Net.Dns — DNS rebinding / SSRF vía resolución DNS
    # =========================================================================

    {
        "id":              "SSRF-024",
        "rule_type":       "sink",
        "symbol":          "System.Net.Dns.GetHostEntry",
        "name":            "Dns.GetHostEntry con hostname dinámico",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "MEDIUM",
        "cwe":             "CWE-918",
        "cvss_base":       5.3,
        "description": (
            "Dns.GetHostEntry con hostname del usuario puede ser usada para "
            "DNS rebinding — el atacante hace que el hostname resuelva a "
            "una IP interna después de la validación. "
            "También puede usarse para confirmar que ciertos hosts existen internamente."
        ),
        "remediation": (
            "No usar hostnames del usuario directamente. "
            "Si es necesario, validar el hostname antes Y verificar la IP resultante "
            "contra la whitelist de IPs/rangos permitidos."
        ),
        "safe_alternative": "Whitelist de hostnames + verificación de IP resultante",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "dns", "rebinding"],
    },
    {
        "id":              "SSRF-025",
        "rule_type":       "sink",
        "symbol":          "System.Net.Dns.GetHostAddresses",
        "name":            "Dns.GetHostAddresses con hostname dinámico",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "MEDIUM",
        "cwe":             "CWE-918",
        "cvss_base":       5.3,
        "description":     "Dns.GetHostAddresses — variante de GetHostEntry, mismo riesgo de DNS rebinding.",
        "remediation":     "Whitelist de hostnames + verificación de IP resultante.",
        "safe_alternative": "Whitelist de hostnames permitidos",
        "frameworks":      ["generic"],
        "tags":            ["ssrf", "dns"],
    },

    # =========================================================================
    #  gRPC — comunicación entre servicios
    # =========================================================================

    {
        "id":              "SSRF-026",
        "rule_type":       "sink",
        "symbol":          "Grpc.Net.Client.GrpcChannel.ForAddress",
        "name":            "gRPC GrpcChannel.ForAddress con dirección dinámica",
        "vulnerability":   "SSRF",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-918",
        "cvss_base":       7.5,
        "description": (
            "GrpcChannel.ForAddress con dirección controlada por el usuario "
            "permite SSRF hacia servicios gRPC internos o externos. "
            "Los servicios gRPC internos pueden no tener autenticación si solo "
            "son accesibles desde la red interna."
        ),
        "remediation": (
            "Hardcodear las direcciones de servicios gRPC en la configuración. "
            "Si es configurable, usar whitelist de endpoints permitidos."
        ),
        "safe_alternative": "GrpcChannel con dirección desde configuración/service discovery",
        "frameworks":      ["grpc", "aspnetcore"],
        "tags":            ["ssrf", "grpc", "microservices"],
    },
]


def get_ssrf_sink_rules() -> list[dict]:
    """Retorna el catálogo completo de reglas de SSRF."""
    return SSRF_SINKS


def get_ssrf_sink_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in SSRF_SINKS}


def get_ssrf_sinks_by_framework(framework: str) -> list[dict]:
    """Retorna las reglas aplicables a un framework específico."""
    return [r for r in SSRF_SINKS if framework in r.get("frameworks", [])]


def get_ssrf_sinks_by_severity(severity: str) -> list[dict]:
    """Retorna los sinks de una severidad específica."""
    return [r for r in SSRF_SINKS if r.get("severity", "") == severity.upper()]


def get_high_confidence_ssrf_sinks() -> list[dict]:
    """Retorna solo los sinks con confianza high o confirmed."""
    return [r for r in SSRF_SINKS if r.get("confidence") in ("high", "confirmed")]