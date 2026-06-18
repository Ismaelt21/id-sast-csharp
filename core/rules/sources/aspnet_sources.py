# =============================================================================
#  csharp-sast / core / rules / sources / aspnet_sources.py
# =============================================================================
#
#  FUENTES DE INPUT DEL ATACANTE EN ASP.NET CORE Y ASP.NET MVC CLÁSICO
#  ─────────────────────────────────────────────────────────────────────
#
#  QUÉ SON LAS SOURCES EN SAST:
#    Puntos donde el atacante puede introducir datos en la aplicación.
#    Todo dato que provenga de una source se considera TAINTED (contaminado)
#    hasta que pase por un sanitizador o llegue a un sink (vulnerabilidad).
#
#  FUENTES IMPLÍCITAS VS EXPLÍCITAS:
#    • Explícitas: el código accede directamente a HttpRequest.Query["id"]
#      → estas son detectadas por el taint_analyzer como source nodes
#    • Implícitas: parámetros de action methods en controladores ASP.NET
#      → ASP.NET Core los bindea automáticamente desde la request
#      → el taint_analyzer las detecta porque el método es entry point
#      → este catálogo NO cubre las implícitas (están en taint_analyzer.py)
#
#  LABELS DE TAINT:
#    USER_INPUT    → controlado directamente por el atacante via HTTP
#    EXTERNAL_INPUT → datos de fuentes externas no totalmente controladas
#    NETWORK_INPUT  → datos crudos de red (sockets, streams)
#
#  CAMPOS DE CADA REGLA:
#    id                 → Identificador único (SRC-ASPNET-NNN)
#    rule_type          → "source" (siempre)
#    symbol             → Prefijo del símbolo resuelto por Roslyn
#    name               → Nombre legible
#    taint_label        → Label de taint asignado
#    severity_multiplier → Factor de ajuste de severidad (1.0 = normal)
#    implicit           → True si la source es implícita (no necesita acceso directo)
#    data_format        → Formato esperado de los datos ("string", "bytes", "stream")
#    authentication_context → Si aplica antes o después de autenticación
#    description        → Descripción del riesgo
#    frameworks         → Lista de frameworks donde aplica
#    tags               → Etiquetas para filtrado
#
# =============================================================================

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
#  ASP.NET CORE — Sources de HttpRequest
# ─────────────────────────────────────────────────────────────────────────────

ASPNET_CORE_SOURCES: list[dict] = [

    # =========================================================================
    #  QueryString — parámetros de URL (?key=value)
    #  Severidad alta: completamente controlados por el atacante, sin autenticación.
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-001",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IQueryCollection",
        "name":                  "HttpRequest.Query (QueryString)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Acceso directo a la QueryString de la petición HTTP. "
            "Completamente controlado por el atacante — sin autenticación ni autorización. "
            "Es el vector más común en SQL Injection, XSS y Path Traversal en ASP.NET Core."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "querystring", "user-input", "unauthenticated"],
    },
    {
        "id":                    "SRC-ASPNET-002",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.Query",
        "name":                  "HttpRequest.Query accessor directo",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Acceso directo a HttpRequest.Query en ASP.NET Core. "
            "Equivalente funcional a IQueryCollection — mismo riesgo."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "querystring", "user-input"],
    },
    {
        "id":                    "SRC-ASPNET-003",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.QueryString",
        "name":                  "HttpRequest.QueryString (string crudo)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "QueryString como string crudo completo (e.g. '?id=1&name=foo'). "
            "Si se parsea manualmente sin sanitización, es vulnerable a parsing attacks."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "querystring", "raw"],
    },

    # =========================================================================
    #  Form Data — cuerpo de peticiones POST (application/x-www-form-urlencoded
    #  o multipart/form-data)
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-004",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IFormCollection",
        "name":                  "HttpRequest.Form (POST body form data)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Datos del formulario POST (application/x-www-form-urlencoded). "
            "Controlado por el atacante — puede enviarse desde cualquier origen "
            "incluso sin JavaScript (HTML form con action a tu servidor)."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "form", "post", "user-input"],
    },
    {
        "id":                    "SRC-ASPNET-005",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.Form",
        "name":                  "HttpRequest.Form accessor",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Acceso directo a HttpRequest.Form — mismos datos de formulario POST.",
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "form", "post"],
    },
    {
        "id":                    "SRC-ASPNET-006",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IFormFile",
        "name":                  "IFormFile (archivo subido)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.2,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "Archivo subido por el usuario vía multipart/form-data. "
            "IFormFile.FileName, IFormFile.ContentType y el contenido del archivo "
            "son completamente controlados por el atacante. "
            "Severity_multiplier 1.2 porque combina path traversal (FileName) "
            "con contenido arbitrario (archivo malicioso)."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "upload", "file", "multipart", "user-input"],
    },
    {
        "id":                    "SRC-ASPNET-007",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IFormFileCollection",
        "name":                  "IFormFileCollection (múltiples archivos subidos)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.2,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description":           "Colección de archivos subidos — mismos riesgos que IFormFile multiplicados.",
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "upload", "files", "multipart"],
    },

    # =========================================================================
    #  Headers HTTP
    #  Severity_multiplier 0.9 — algo menos explotables que query/body porque
    #  algunos browsers y proxies los filtran, pero sigue siendo tainted.
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-008",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IHeaderDictionary",
        "name":                  "HttpRequest.Headers",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Headers HTTP de la petición. Controlados por el cliente. "
            "Relevante para: Header Injection (X-Forwarded-For, User-Agent manipulado), "
            "Log Injection (User-Agent en logs), SQL Injection vía headers custom, "
            "SSRF vía Host header manipulation."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "headers", "user-input", "header-injection"],
    },
    {
        "id":                    "SRC-ASPNET-009",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.Headers",
        "name":                  "HttpRequest.Headers accessor",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Acceso directo a HttpRequest.Headers.",
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "headers"],
    },

    # =========================================================================
    #  Body — cuerpo crudo de la request (JSON, XML, binario)
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-010",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.Body",
        "name":                  "HttpRequest.Body (raw body stream)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "Raw body stream de la petición HTTP. "
            "Controlado completamente por el cliente. "
            "Relevante cuando el body se lee manualmente (sin model binding). "
            "Especialmente peligroso si se parsea como XML (XXE) o se deserializa."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "body", "stream", "raw", "user-input"],
    },
    {
        "id":                    "SRC-ASPNET-011",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.BodyReader",
        "name":                  "HttpRequest.BodyReader (PipeReader)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "any",
        "description": (
            "HttpRequest.BodyReader es la API moderna (PipeReader) para leer el body. "
            "Mismo riesgo que Body — datos completamente controlados por el cliente."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "body", "pipeline", "bytes"],
    },

    # =========================================================================
    #  Route Parameters — parámetros extraídos de la URL (/api/users/{id})
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-012",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Routing.RouteData.Values",
        "name":                  "RouteData.Values (route parameters)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Parámetros de ruta extraídos de la URL (p.ej. /users/{id}). "
            "Controlados por el atacante aunque se ven como parte de la URL 'limpia'. "
            "Son tainted igual que query strings."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "route", "url", "user-input"],
    },
    {
        "id":                    "SRC-ASPNET-013",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.RouteValues",
        "name":                  "HttpRequest.RouteValues",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Acceso a RouteValues directamente desde HttpRequest — mismos datos de ruta.",
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "route", "url"],
    },

    # =========================================================================
    #  Path — segmento de ruta de la URL
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-014",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.Path",
        "name":                  "HttpRequest.Path (URL path segment)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Path de la URL de la petición (/api/files/userfile.txt). "
            "Severity_multiplier 1.1 — especialmente relevante para Path Traversal "
            "si se usa para construir rutas del sistema de archivos."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "path", "url", "path-traversal"],
    },
    {
        "id":                    "SRC-ASPNET-015",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.PathBase",
        "name":                  "HttpRequest.PathBase",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "PathBase de la URL — path base de la aplicación. Mismo riesgo que Path.",
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "path", "url"],
    },

    # =========================================================================
    #  Cookies — ligeramente menos peligrosas pero tainted
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-016",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IRequestCookieCollection",
        "name":                  "HttpRequest.Cookies",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Cookies de la petición HTTP. Controladas por el cliente. "
            "Severity_multiplier 0.85 — menos accesibles que query strings para CSRF, "
            "pero igualmente peligrosas para SQL Injection y Log Injection. "
            "El atacante puede manipularlas directamente desde el browser."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "cookies", "user-input"],
    },
    {
        "id":                    "SRC-ASPNET-017",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest.Cookies",
        "name":                  "HttpRequest.Cookies accessor",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Acceso directo a HttpRequest.Cookies.",
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "cookies"],
    },

    # =========================================================================
    #  HttpContext — acceso al contexto completo
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-018",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpContext.Request",
        "name":                  "HttpContext.Request",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Acceso al HttpRequest completo vía HttpContext. "
            "Cualquier propiedad de Request es tainted. "
            "Marked as implicit porque es el punto de acceso principal al request."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "context", "request"],
    },
    {
        "id":                    "SRC-ASPNET-019",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Mvc.ControllerBase.Request",
        "name":                  "ControllerBase.Request",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Propiedad Request en ControllerBase de ASP.NET Core. "
            "Punto de acceso al HttpRequest dentro de un controller."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "mvc", "controller", "request"],
    },
    {
        "id":                    "SRC-ASPNET-020",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.IHttpContextAccessor.HttpContext",
        "name":                  "IHttpContextAccessor.HttpContext",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "IHttpContextAccessor permite acceder al HttpContext desde servicios "
            "inyectados (capas de servicio, repositorios). "
            "Si un servicio accede a Request via IHttpContextAccessor, "
            "el taint se propaga a través de la capa de servicio."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "context", "accessor", "service-layer"],
    },

    # =========================================================================
    #  Minimal APIs — acceso a HttpContext en lambdas
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-021",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpContext",
        "name":                  "HttpContext en Minimal API endpoint",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "HttpContext inyectado directamente en un endpoint de Minimal API. "
            "app.MapGet('/endpoint', (HttpContext ctx) => ctx.Request.Query['id'])"
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "minimal-api", "context"],
    },
    {
        "id":                    "SRC-ASPNET-022",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.Http.HttpRequest",
        "name":                  "HttpRequest en Minimal API endpoint",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "HttpRequest inyectado directamente en un endpoint de Minimal API. "
            "app.MapPost('/endpoint', async (HttpRequest req) => { var body = await req.ReadFromJsonAsync<T>(); })"
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["http", "minimal-api", "request"],
    },

    # =========================================================================
    #  Claims / Identity — datos del usuario autenticado
    #  Severity_multiplier reducido porque requieren autenticación,
    #  pero son tainted si el sistema de identidad puede ser manipulado.
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-023",
        "rule_type":             "source",
        "symbol":                "System.Security.Claims.ClaimsPrincipal",
        "name":                  "ClaimsPrincipal.Claims (datos del usuario autenticado)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "authenticated",
        "description": (
            "Claims del usuario autenticado (nombre, email, roles, claims custom). "
            "Severity_multiplier 0.7 — requieren autenticación, pero son tainted "
            "si el sistema de identidad permite que el usuario controle sus propios claims "
            "(p.ej. claims custom en JWT que el cliente puede modificar si el secret es débil)."
        ),
        "frameworks":            ["aspnetcore", "aspnet_mvc"],
        "tags":                  ["identity", "claims", "authenticated", "jwt"],
    },
    {
        "id":                    "SRC-ASPNET-024",
        "rule_type":             "source",
        "symbol":                "System.Security.Claims.ClaimsIdentity.FindFirst",
        "name":                  "ClaimsIdentity.FindFirst (claim individual)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "authenticated",
        "description": (
            "ClaimsIdentity.FindFirst extrae un claim específico. "
            "Si el claim se usa en queries SQL o como ruta de archivo → tainted."
        ),
        "frameworks":            ["aspnetcore", "aspnet_mvc"],
        "tags":                  ["identity", "claims", "authenticated"],
    },

    # =========================================================================
    #  SignalR — comunicación en tiempo real
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-025",
        "rule_type":             "source",
        "symbol":                "Microsoft.AspNetCore.SignalR.Hub.Context",
        "name":                  "SignalR Hub.Context (datos de la conexión)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Context de un Hub SignalR. Los métodos del Hub reciben parámetros "
            "de los clientes WebSocket — completamente controlados por el atacante "
            "si el cliente es malicioso."
        ),
        "frameworks":            ["aspnetcore"],
        "tags":                  ["signalr", "websocket", "realtime", "user-input"],
    },

    # =========================================================================
    #  ASP.NET MVC CLÁSICO (System.Web) — framework legacy
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-MVC-001",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.QueryString",
        "name":                  "HttpRequest.QueryString (ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "QueryString de System.Web.HttpRequest en ASP.NET MVC clásico. "
            "Equivalente a IQueryCollection en ASP.NET Core — mismo riesgo."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "querystring", "user-input", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-002",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.Form",
        "name":                  "HttpRequest.Form (POST body, ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Datos de formulario POST en ASP.NET MVC clásico (System.Web).",
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "form", "post", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-003",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.Headers",
        "name":                  "HttpRequest.Headers (ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Headers HTTP en ASP.NET MVC clásico.",
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "headers", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-004",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.Cookies",
        "name":                  "HttpRequest.Cookies (ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description":           "Cookies en ASP.NET MVC clásico.",
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "cookies", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-005",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.ServerVariables",
        "name":                  "HttpRequest.ServerVariables",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Variables de servidor HTTP en ASP.NET MVC clásico. "
            "Incluye HTTP_USER_AGENT, HTTP_REFERER, REMOTE_ADDR, etc. "
            "Severity_multiplier 0.8 — algunas variables son del servidor, "
            "pero las que empiezan con HTTP_ son controladas por el cliente."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "server-variables", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-006",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.InputStream",
        "name":                  "HttpRequest.InputStream (raw body, ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description":           "Raw body stream en ASP.NET MVC clásico — mismo riesgo que Body en ASP.NET Core.",
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "body", "stream", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-007",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.Params",
        "name":                  "HttpRequest.Params (combina Query + Form + Cookies + ServerVariables)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Params combina QueryString, Form, Cookies y ServerVariables en una colección. "
            "Severity_multiplier 1.1 — es el mayor superficie de ataque: "
            "el atacante puede inyectar via cualquiera de las 4 fuentes."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "params", "combined", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-008",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.Files",
        "name":                  "HttpRequest.Files (archivos subidos, ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.2,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "HttpPostedFile y HttpFileCollection en ASP.NET MVC clásico. "
            "FileName, ContentType y el stream del archivo son controlados por el atacante."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "upload", "files", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-009",
        "rule_type":             "source",
        "symbol":                "System.Web.HttpRequest.Url",
        "name":                  "HttpRequest.Url (URL completa)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "URL completa de la petición en ASP.NET MVC clásico. "
            "Si se usa para construir rutas de archivo o queries → tainted."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "url", "system.web"],
    },
    {
        "id":                    "SRC-ASPNET-MVC-010",
        "rule_type":             "source",
        "symbol":                "System.Web.Mvc.Controller.Request",
        "name":                  "Controller.Request (ASP.NET MVC clásico)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description":           "Propiedad Request en Controller de ASP.NET MVC clásico (System.Web).",
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "mvc", "controller", "system.web"],
    },

    # =========================================================================
    #  WebForms — endpoints de formulario
    # =========================================================================

    {
        "id":                    "SRC-ASPNET-WF-001",
        "rule_type":             "source",
        "symbol":                "System.Web.UI.Page.Request",
        "name":                  "WebForms Page.Request",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Propiedad Request en una WebForms Page. "
            "Acceso al HttpRequest en el modelo de código subyacente de WebForms."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["http", "webforms", "page", "request"],
    },
    {
        "id":                    "SRC-ASPNET-WF-002",
        "rule_type":             "source",
        "symbol":                "System.Web.UI.WebControls.TextBox.Text",
        "name":                  "WebForms TextBox.Text",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.95,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Propiedad Text de un WebForms TextBox — input directo del usuario. "
            "Si se usa sin validación en queries o paths → tainted."
        ),
        "frameworks":            ["aspnet_mvc"],
        "tags":                  ["webforms", "input", "textbox", "user-input"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCIONES DE ACCESO AL CATÁLOGO
# ─────────────────────────────────────────────────────────────────────────────

def get_aspnet_source_rules() -> list[dict]:
    """Retorna el catálogo completo de sources ASP.NET Core y MVC."""
    return ASPNET_CORE_SOURCES


def get_aspnet_source_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in ASPNET_CORE_SOURCES}


def get_aspnetcore_sources() -> list[dict]:
    """Retorna solo las sources de ASP.NET Core (no MVC clásico ni WebForms)."""
    return [r for r in ASPNET_CORE_SOURCES if r.get("frameworks") == ["aspnetcore"]]


def get_aspnet_mvc_sources() -> list[dict]:
    """Retorna solo las sources de ASP.NET MVC clásico (System.Web)."""
    return [r for r in ASPNET_CORE_SOURCES if "aspnet_mvc" in r.get("frameworks", [])]


def get_high_severity_sources() -> list[dict]:
    """
    Retorna sources con severity_multiplier >= 1.0.
    Estas son las más críticas para el taint analysis.
    """
    return [r for r in ASPNET_CORE_SOURCES if r.get("severity_multiplier", 1.0) >= 1.0]


def get_unauthenticated_sources() -> list[dict]:
    """
    Retorna sources accesibles sin autenticación.
    Máximo riesgo porque cualquier atacante puede explotarlas.
    """
    return [
        r for r in ASPNET_CORE_SOURCES
        if r.get("authentication_context") == "any"
    ]


def get_file_upload_sources() -> list[dict]:
    """Retorna sources relacionadas con subida de archivos."""
    return [r for r in ASPNET_CORE_SOURCES if "upload" in r.get("tags", [])]


def get_source_taint_labels() -> dict[str, str]:
    """
    Retorna mapa {symbol_prefix: taint_label} para lookup rápido por el TaintAnalyzer.
    """
    return {rule["symbol"]: rule["taint_label"] for rule in ASPNET_CORE_SOURCES}


def get_source_severity_multipliers() -> dict[str, float]:
    """
    Retorna mapa {symbol_prefix: severity_multiplier} para ajuste de severidad
    en el VulnerabilityClassifier.
    """
    return {
        rule["symbol"]: rule.get("severity_multiplier", 1.0)
        for rule in ASPNET_CORE_SOURCES
    }