# =============================================================================
#  csharp-sast / core / rules / sanitizers / validation_sanitizers.py
# =============================================================================
#
#  CATÁLOGO DE SANITIZADORES DE VALIDACIÓN PARA C#
#  ──────────────────────────────────────────────────
#  Define los métodos de .NET que validan datos del usuario mediante
#  conversión de tipos, parsing estricto, whitelists o verificaciones
#  de formato, interrumpiendo el flujo de taint cuando el dato supera
#  la validación.
#
#  VALIDACIÓN VS ENCODING (distinción crítica):
#    • Encoding (encoding_sanitizers.py):
#        Transforma el dato para que sea seguro en un contexto de salida.
#        El dato original sigue siendo "sucio" — solo el encoded es seguro.
#        Ejemplo: HtmlEncode("<script>") → "&lt;script&gt;"
#
#    • Validación (este módulo):
#        Verifica que el dato cumple un contrato (tipo, formato, rango).
#        Si la validación pasa → el dato se considera seguro para ese uso.
#        Si falla → el flujo se interrumpe (excepción o retorna false).
#        Ejemplo: int.TryParse(userInput, out int id) → id solo puede ser int
#
#  CÓMO FUNCIONA LA VALIDACIÓN COMO SANITIZADOR:
#    Los validadores de tipo (TryParse, Guid.TryParse) son sanitizadores
#    ABSOLUTOS para inyecciones de string — un entero válido nunca puede
#    contener SQL injection, path traversal o command injection.
#    El taint_analyzer debe propagar taint al string original pero NO
#    al valor convertido (out parameter o return value).
#
#    Ejemplo correcto de análisis:
#      var input = Request.Query["id"];          // TAINTED (string)
#      if (!int.TryParse(input, out int id))     // id es un int, NO TAINTED
#          return BadRequest();
#      var query = $"SELECT * WHERE Id = {id}";  // SEGURO — id es int
#
#    Ejemplo de falso negativo a evitar:
#      var input = Request.Query["id"];           // TAINTED
#      int.TryParse(input, out int id);           // resultado ignorado
#      var query = $"SELECT * WHERE Id = {input}"; // TAINTED — el string original
#
#  CONFIDENCE:
#    0.95-1.0 → sanitizadores de tipo (int, guid, enum) — prácticamente perfectos
#    0.80-0.95 → validaciones de formato (regex, custom validators)
#    0.50-0.80 → validaciones de whitelist (depende de la implementación)
#    < 0.50    → verificaciones parciales o contexto-específicas
#
#  CAMPOS (idénticos a encoding_sanitizers.py):
#    id, rule_type, symbol, name, sanitizes, sanitizer_type,
#    encoding_context, confidence, limitations, description,
#    frameworks, tags
#
#  NOTA SOBRE encoding_context EN VALIDACIÓN:
#    Para validadores de tipo, encoding_context representa el contexto
#    donde el valor VALIDADO es seguro (no el contexto de output encoding).
#    Ejemplo: int.TryParse → encoding_context: ["sql_query", "command_argument"]
#    significa que un int válido es seguro para usar en queries SQL y comandos.
#
# =============================================================================

from __future__ import annotations

VALIDATION_SANITIZERS: list[dict] = [

    # =========================================================================
    #  SECCIÓN 1: VALIDADORES DE TIPO NUMÉRICO
    #  Los más fuertes — un número válido no puede contener inyección de string.
    #  El taint se elimina del OUT parameter / valor retornado, no del string.
    # =========================================================================

    {
        "id":              "SAN-VAL-001",
        "rule_type":       "sanitizer",
        "symbol":          "System.Int32.TryParse",
        "name":            "int.TryParse — validación y conversión a entero",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                            "XSS", "OPEN_REDIRECT", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path",
                             "html_body", "url_value", "log_entry"],
        "confidence":      0.97,
        "limitations": (
            "Confidence 0.97 — sanitiza el valor OUT (int), NO el string original. "
            "El taint_analyzer debe verificar que el código usa el parámetro 'out int' "
            "y no el string original en el sink. "
            "Si el resultado bool de TryParse se ignora y se usa el string → no sanitizado. "
            "No sanitiza: SSRF (una IP válida sigue siendo SSRF), "
            "XXE (un número no protege el parser XML), "
            "INSECURE_DESERIALIZATION."
        ),
        "description": (
            "int.TryParse() convierte un string a int de forma segura. "
            "Un int válido (−2,147,483,648 a 2,147,483,647) nunca puede contener: "
            "SQL injection (sin comillas ni palabras clave), "
            "Command injection (sin metacaracteres de shell), "
            "Path traversal (sin slash ni puntos), "
            "XSS (sin < > ni script tags). "
            "Patrón seguro: if (!int.TryParse(input, out int id)) return BadRequest(); "
            "A partir de ahí 'id' puede usarse directamente sin peligro."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc", "wcf"],
        "tags":            ["validation", "type-check", "integer", "parse", "strong"],
    },
    {
        "id":              "SAN-VAL-002",
        "rule_type":       "sanitizer",
        "symbol":          "System.Int64.TryParse",
        "name":            "long.TryParse — validación y conversión a long",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                            "XSS", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path", "log_entry"],
        "confidence":      0.97,
        "limitations": (
            "Mismas limitaciones que int.TryParse. "
            "El taint se elimina del long resultante, no del string."
        ),
        "description": (
            "long.TryParse() — versión de 64 bits de int.TryParse. "
            "Mismo comportamiento de sanitización — el long resultante es seguro "
            "para SQL, comandos, paths y logs."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "type-check", "long", "parse", "strong"],
    },
    {
        "id":              "SAN-VAL-003",
        "rule_type":       "sanitizer",
        "symbol":          "System.Int16.TryParse",
        "name":            "short.TryParse — validación y conversión a short",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "log_entry"],
        "confidence":      0.97,
        "limitations":     "Mismas limitaciones que int.TryParse.",
        "description": (
            "short.TryParse() — versión de 16 bits. "
            "Rango más restringido (−32,768 a 32,767) — aún más seguro que int."
        ),
        "frameworks":      ["generic"],
        "tags":            ["validation", "type-check", "short", "parse"],
    },
    {
        "id":              "SAN-VAL-004",
        "rule_type":       "sanitizer",
        "symbol":          "System.UInt32.TryParse",
        "name":            "uint.TryParse — validación y conversión a uint (sin signo)",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path"],
        "confidence":      0.98,
        "limitations": (
            "Solo acepta valores positivos (0 a 4,294,967,295). "
            "Aún más restrictivo que int — mayor confidence."
        ),
        "description": (
            "uint.TryParse() — entero sin signo. "
            "Solo acepta números positivos — ideal para IDs de recursos."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "type-check", "uint", "parse", "positive"],
    },
    {
        "id":              "SAN-VAL-005",
        "rule_type":       "sanitizer",
        "symbol":          "System.Double.TryParse",
        "name":            "double.TryParse — validación y conversión a double",
        "sanitizes":       ["SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "log_entry"],
        "confidence":      0.92,
        "limitations": (
            "Confidence 0.92 — los doubles admiten NaN, Infinity, notación científica. "
            "Un double no puede contener SQL injection pero sí valores especiales "
            "que pueden causar comportamientos inesperados. "
            "Preferir decimal para valores monetarios."
        ),
        "description": (
            "double.TryParse() — validación de número de punto flotante. "
            "Sanitiza SQL injection y log injection pero con menor confianza "
            "que int/long por los valores especiales admitidos."
        ),
        "frameworks":      ["generic"],
        "tags":            ["validation", "type-check", "double", "float", "parse"],
    },
    {
        "id":              "SAN-VAL-006",
        "rule_type":       "sanitizer",
        "symbol":          "System.Decimal.TryParse",
        "name":            "decimal.TryParse — validación y conversión a decimal",
        "sanitizes":       ["SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "log_entry"],
        "confidence":      0.95,
        "limitations": (
            "No acepta NaN ni Infinity — más restrictivo que double. "
            "Ideal para valores monetarios y de precisión financiera."
        ),
        "description": (
            "decimal.TryParse() — validación de número decimal de alta precisión. "
            "Mayor confianza que double — no acepta valores especiales como NaN."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "type-check", "decimal", "monetary", "parse"],
    },
    {
        "id":              "SAN-VAL-007",
        "rule_type":       "sanitizer",
        "symbol":          "System.Boolean.TryParse",
        "name":            "bool.TryParse — validación y conversión a bool",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "log_entry"],
        "confidence":      0.99,
        "limitations": (
            "Solo acepta 'True' o 'False' (case-insensitive). "
            "Prácticamente imposible que un bool cause inyección."
        ),
        "description": (
            "bool.TryParse() — validación de valor booleano. "
            "Confidence 0.99 — solo dos valores posibles (true/false), "
            "imposible contener injection."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "type-check", "boolean", "parse", "very-strong"],
    },

    # =========================================================================
    #  SECCIÓN 2: GUID / UUID — validación de identificadores únicos
    #  El más fuerte sanitizador para IDs de recursos — formato rígido.
    # =========================================================================

    {
        "id":              "SAN-VAL-008",
        "rule_type":       "sanitizer",
        "symbol":          "System.Guid.TryParse",
        "name":            "Guid.TryParse — validación y conversión a GUID/UUID",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                            "XSS", "SSRF", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path",
                             "url_value", "log_entry", "html_body"],
        "confidence":      0.99,
        "limitations": (
            "Solo acepta el formato UUID exacto: "
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (32 hex + 4 guiones). "
            "Un GUID válido no puede contener NINGÚN caracter de injection. "
            "El taint se elimina del Guid resultante, no del string."
        ),
        "description": (
            "Guid.TryParse() es el sanitizador de validación más fuerte en .NET. "
            "Un GUID válido solo contiene dígitos hexadecimales (0-9, a-f) y guiones. "
            "Es matemáticamente imposible que un GUID válido contenga: "
            "SQL injection (sin comillas, sin palabras clave), "
            "Command injection (sin metacaracteres), "
            "Path traversal (sin slash ni puntos), "
            "XSS (sin < > ni script), "
            "SSRF (no es una URL). "
            "Patrón ideal para IDs de recursos: GET /api/users/{id} donde id es GUID. "
            "if (!Guid.TryParse(idStr, out Guid userId)) return NotFound();"
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc", "wcf"],
        "tags":            ["validation", "type-check", "guid", "uuid", "id",
                            "very-strong", "recommended"],
    },
    {
        "id":              "SAN-VAL-009",
        "rule_type":       "sanitizer",
        "symbol":          "System.Guid.TryParseExact",
        "name":            "Guid.TryParseExact — validación de GUID con formato exacto",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                            "XSS", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path", "log_entry"],
        "confidence":      0.99,
        "limitations":     "Aún más restrictivo que TryParse — requiere un formato específico.",
        "description": (
            "Guid.TryParseExact() con formato específico (N, D, B, P, X). "
            "Más restrictivo que TryParse — misma seguridad, mayor control del formato."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "guid", "uuid", "exact", "very-strong"],
    },

    # =========================================================================
    #  SECCIÓN 3: ENUM — validación por conjunto de valores permitidos
    #  Excelente para parámetros que deben estar en un conjunto conocido.
    # =========================================================================

    {
        "id":              "SAN-VAL-010",
        "rule_type":       "sanitizer",
        "symbol":          "System.Enum.TryParse",
        "name":            "Enum.TryParse — validación por conjunto de valores conocidos",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                            "XSS", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path",
                             "html_body", "log_entry"],
        "confidence":      0.96,
        "limitations": (
            "Confidence 0.96 — el Enum resultante es completamente seguro. "
            "IMPORTANTE: usar el valor Enum resultante, no el string original. "
            "Con ignoreCase=true es más permisivo pero sigue siendo seguro. "
            "Si el Enum tiene valores numéricos y el string es un número, "
            "Enum.TryParse puede parsear números fuera del conjunto definido "
            "— usar Enum.IsDefined() adicionalmente para valores críticos."
        ),
        "description": (
            "Enum.TryParse() convierte un string a un valor de enum. "
            "El valor resultante solo puede ser uno de los valores definidos en el enum. "
            "Ideal para parámetros como: status, category, sort_order, action_type. "
            "Patrón: if (!Enum.TryParse<OrderStatus>(input, out var status)) return BadRequest(); "
            "El enum resultante es una whitelist implícita de valores permitidos."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "enum", "whitelist", "type-check", "strong"],
    },
    {
        "id":              "SAN-VAL-011",
        "rule_type":       "sanitizer",
        "symbol":          "System.Enum.IsDefined",
        "name":            "Enum.IsDefined — verificación de valor en conjunto de enum",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "XSS"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "html_body"],
        "confidence":      0.88,
        "limitations": (
            "Confidence 0.88 — IsDefined verifica si el valor está en el enum "
            "pero no convierte el tipo. "
            "El código debe usar el valor casteado, no el string. "
            "Menos fuerte que TryParse porque aún requiere un cast manual."
        ),
        "description": (
            "Enum.IsDefined() verifica si un valor es un miembro válido del enum. "
            "Usar en combinación con (MyEnum)Enum.Parse() o como verificación adicional "
            "después de TryParse cuando se necesita confirmar que el int está en el enum."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "enum", "check", "whitelist"],
    },

    # =========================================================================
    #  SECCIÓN 4: FECHA Y TIEMPO — validación de formatos de fecha
    # =========================================================================

    {
        "id":              "SAN-VAL-012",
        "rule_type":       "sanitizer",
        "symbol":          "System.DateTime.TryParse",
        "name":            "DateTime.TryParse — validación y conversión de fecha",
        "sanitizes":       ["SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "log_entry"],
        "confidence":      0.90,
        "limitations": (
            "Confidence 0.90 — DateTime válido no puede contener SQL injection. "
            "Sin embargo, el formato de fecha puede variar según cultura (MM/DD vs DD/MM) "
            "lo que puede causar errores de lógica (no de seguridad). "
            "Preferir TryParseExact para mayor control del formato."
        ),
        "description": (
            "DateTime.TryParse() valida que el string es una fecha/hora válida. "
            "Un DateTime válido no puede contener SQL injection ni log injection. "
            "Sanitiza el DateTime resultante — usar ese valor, no el string."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "datetime", "date", "parse"],
    },
    {
        "id":              "SAN-VAL-013",
        "rule_type":       "sanitizer",
        "symbol":          "System.DateTime.TryParseExact",
        "name":            "DateTime.TryParseExact — validación de fecha con formato exacto",
        "sanitizes":       ["SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "log_entry"],
        "confidence":      0.95,
        "limitations": (
            "El formato debe estar hardcodeado (no puede venir del usuario). "
            "Mayor confianza que TryParse por formato controlado."
        ),
        "description": (
            "DateTime.TryParseExact() con formato hardcodeado. "
            "Mayor confianza que TryParse — el formato está completamente controlado. "
            "Patrón: DateTime.TryParseExact(input, 'yyyy-MM-dd', CultureInfo.InvariantCulture, ...)."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "datetime", "exact", "format-controlled"],
    },
    {
        "id":              "SAN-VAL-014",
        "rule_type":       "sanitizer",
        "symbol":          "System.DateTimeOffset.TryParse",
        "name":            "DateTimeOffset.TryParse — validación de fecha con timezone",
        "sanitizes":       ["SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "log_entry"],
        "confidence":      0.90,
        "limitations":     "Mismas limitaciones que DateTime.TryParse.",
        "description": (
            "DateTimeOffset.TryParse() — variante con información de timezone. "
            "Mismo nivel de sanitización que DateTime.TryParse."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "datetimeoffset", "timezone", "parse"],
    },
    {
        "id":              "SAN-VAL-015",
        "rule_type":       "sanitizer",
        "symbol":          "System.TimeSpan.TryParse",
        "name":            "TimeSpan.TryParse — validación de intervalo de tiempo",
        "sanitizes":       ["SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "log_entry"],
        "confidence":      0.93,
        "limitations":     "El TimeSpan resultante es seguro — el string original no.",
        "description": (
            "TimeSpan.TryParse() valida y convierte un string a TimeSpan. "
            "Un TimeSpan válido no puede contener injection."
        ),
        "frameworks":      ["generic"],
        "tags":            ["validation", "timespan", "duration", "parse"],
    },

    # =========================================================================
    #  SECCIÓN 5: VALIDACIÓN DE PATH — prevención de Path Traversal
    # =========================================================================

    {
        "id":              "SAN-VAL-016",
        "rule_type":       "sanitizer",
        "symbol":          "System.IO.Path.GetFileName",
        "name":            "Path.GetFileName — eliminación de componentes de directorio",
        "sanitizes":       ["PATH_TRAVERSAL"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["file_path"],
        "confidence":      0.80,
        "limitations": (
            "Confidence 0.80 — Path.GetFileName es necesario pero NO suficiente. "
            "Elimina componentes de directorio pero el resultado puede ser un nombre "
            "de archivo válido que sobrescriba un archivo del sistema. "
            "SIEMPRE combinar con: "
            "1. Path.Combine con directorio base fijo "
            "2. Path.GetFullPath para resolver la ruta "
            "3. Verificar que el resultado está dentro del directorio base. "
            "Path.GetFileName('/etc/passwd') → 'passwd' (nombre sin peligro de traversal "
            "pero aún puede ser un nombre de archivo peligroso si se combina mal)."
        ),
        "description": (
            "Path.GetFileName() extrae solo el nombre de archivo, eliminando "
            "toda la parte de directorio (incluyendo '../'). "
            "Previene path traversal en el NOMBRE del archivo, pero no garantiza "
            "que el archivo esté en el directorio permitido. "
            "Usar SIEMPRE como primera línea de defensa, combinado con "
            "Path.GetFullPath() + validación de directorio base."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "path", "traversal", "file", "partial"],
    },
    {
        "id":              "SAN-VAL-017",
        "rule_type":       "sanitizer",
        "symbol":          "System.IO.Path.GetFullPath",
        "name":            "Path.GetFullPath — resolución y normalización de ruta absoluta",
        "sanitizes":       ["PATH_TRAVERSAL"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["file_path"],
        "confidence":      0.82,
        "limitations": (
            "Confidence 0.82 — Path.GetFullPath normaliza la ruta pero NO verifica "
            "que esté dentro del directorio permitido. "
            "DEBE ir seguido de una verificación: "
            "if (!fullPath.StartsWith(allowedBaseDir, StringComparison.OrdinalIgnoreCase)) "
            "    throw new SecurityException(); "
            "Sin esa verificación, GetFullPath solo resuelve '../' pero no bloquea el traversal."
        ),
        "description": (
            "Path.GetFullPath() resuelve la ruta absoluta normalizada, "
            "eliminando redundancias como '../' y '//'. "
            "Permite comparar la ruta resultante con el directorio base permitido. "
            "Patrón completo seguro: "
            "var full = Path.GetFullPath(Path.Combine(baseDir, userInput)); "
            "if (!full.StartsWith(baseDir, OrdinalIgnoreCase)) throw new SecurityException();"
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "path", "traversal", "normalize", "partial"],
    },
    {
        "id":              "SAN-VAL-018",
        "rule_type":       "sanitizer",
        "symbol":          "System.IO.Path.GetExtension",
        "name":            "Path.GetExtension — extracción de extensión de archivo",
        "sanitizes":       ["PATH_TRAVERSAL"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["file_path"],
        "confidence":      0.65,
        "limitations": (
            "Confidence 0.65 — solo extrae la extensión, no valida la seguridad del path. "
            "Útil para validar la extensión permitida (whitelist), "
            "pero NO por sí solo previene path traversal. "
            "Usar como parte de validación de uploads: "
            "var ext = Path.GetExtension(file.FileName).ToLower(); "
            "if (!allowedExtensions.Contains(ext)) throw new SecurityException();"
        ),
        "description": (
            "Path.GetExtension() extrae la extensión de un nombre de archivo. "
            "Útil para whitelistear extensiones permitidas en uploads. "
            "Sanitizador parcial — solo válida la extensión, no la ruta completa."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "path", "extension", "file", "partial"],
    },
    {
        "id":              "SAN-VAL-019",
        "rule_type":       "sanitizer",
        "symbol":          "System.IO.Path.GetFileNameWithoutExtension",
        "name":            "Path.GetFileNameWithoutExtension — nombre sin extensión ni directorio",
        "sanitizes":       ["PATH_TRAVERSAL"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["file_path"],
        "confidence":      0.78,
        "limitations": (
            "Elimina directorios y extensión — el nombre resultante es más seguro "
            "que el input original, pero aún puede contener caracteres especiales. "
            "Combinar con validación de caracteres del nombre de archivo."
        ),
        "description": (
            "Path.GetFileNameWithoutExtension() elimina tanto la parte de directorio "
            "como la extensión. Resultado más seguro que GetFileName. "
            "Usar cuando se necesita el nombre base para construir rutas."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "path", "filename", "extension", "partial"],
    },

    # =========================================================================
    #  SECCIÓN 6: VALIDACIÓN DE URL — prevención de SSRF y Open Redirect
    # =========================================================================

    {
        "id":              "SAN-VAL-020",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl",
        "name":            "IUrlHelper.IsLocalUrl — verificación de URL local (ASP.NET Core)",
        "sanitizes":       ["OPEN_REDIRECT"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["url_value", "redirect_url"],
        "confidence":      0.96,
        "limitations": (
            "Confidence 0.96 — IsLocalUrl() es el método recomendado por Microsoft "
            "para validar URLs de redirect en ASP.NET Core. "
            "Solo acepta URLs relativas (que empiezan con '/' pero no con '//'), "
            "rechazando URLs absolutas (http://, https://) y protocol-relative URLs (//evil.com). "
            "NO previene SSRF — solo previene Open Redirect en Redirect()."
        ),
        "description": (
            "IUrlHelper.IsLocalUrl() verifica que una URL es relativa al servidor actual. "
            "Previene Open Redirect filtrando URLs externas. "
            "Patrón estándar en ASP.NET Core: "
            "if (!Url.IsLocalUrl(returnUrl)) return Forbid(); "
            "return Redirect(returnUrl); "
            "Rechaza: http://evil.com, //evil.com, javascript:alert(1)."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["validation", "url", "local", "redirect", "open-redirect"],
    },
    {
        "id":              "SAN-VAL-021",
        "rule_type":       "sanitizer",
        "symbol":          "System.Uri.TryCreate",
        "name":            "Uri.TryCreate — validación y parseo de URI",
        "sanitizes":       ["SSRF", "OPEN_REDIRECT"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["url_value"],
        "confidence":      0.72,
        "limitations": (
            "Confidence 0.72 — Uri.TryCreate solo verifica que la URI es válida "
            "sintácticamente, NO que es segura semánticamente. "
            "http://169.254.169.254 es una URI válida → no bloquea SSRF. "
            "Para SSRF usar Uri.TryCreate + verificación del Host contra whitelist. "
            "Patrón seguro: "
            "if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri)) return BadRequest(); "
            "if (!allowedHosts.Contains(uri.Host)) return Forbid();"
        ),
        "description": (
            "Uri.TryCreate() parsea una URL y verifica que es sintácticamente válida. "
            "El objeto Uri resultante permite acceder a Host, Scheme, Port, etc. "
            "para validaciones adicionales. "
            "Por sí solo es un sanitizador parcial — debe combinarse con "
            "verificación de host para SSRF o IsLocalUrl para Open Redirect."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "url", "uri", "parse", "partial"],
    },
    {
        "id":              "SAN-VAL-022",
        "rule_type":       "sanitizer",
        "symbol":          "System.Uri.IsWellFormedUriString",
        "name":            "Uri.IsWellFormedUriString — verificación de formato de URI",
        "sanitizes":       ["OPEN_REDIRECT"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["url_value"],
        "confidence":      0.60,
        "limitations": (
            "Confidence 0.60 — verifica formato pero no seguridad. "
            "Una URL mal formada es rechazada, pero una bien formada y maliciosa pasa. "
            "Sanitizador muy parcial — solo útil como primera validación básica."
        ),
        "description": (
            "Uri.IsWellFormedUriString() verifica que el string tiene formato de URI válido. "
            "Muy básico — no verifica si la URI es segura."
        ),
        "frameworks":      ["generic"],
        "tags":            ["validation", "url", "format", "partial", "basic"],
    },

    # =========================================================================
    #  SECCIÓN 7: REGEX — validación por expresión regular (whitelist)
    # =========================================================================

    {
        "id":              "SAN-VAL-023",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.RegularExpressions.Regex.IsMatch",
        "name":            "Regex.IsMatch — validación por patrón (whitelist/blacklist)",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                            "XSS", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "file_path",
                             "html_body", "log_entry"],
        "confidence":      0.70,
        "limitations": (
            "Confidence 0.70 — la efectividad DEPENDE COMPLETAMENTE del patrón regex. "
            "Whitelist (solo chars permitidos) → alta confianza. "
            "Blacklist (bloquear chars peligrosos) → baja confianza (bypass posible). "
            "El taint_analyzer reporta confianza 0.70 genérica porque no puede "
            "analizar el patrón en tiempo estático. "
            "Ejemplo de whitelist buena: ^[a-zA-Z0-9_-]+$ "
            "Ejemplo de blacklist mala: ^(?!.*DROP).*$ (bypasseable)."
        ),
        "description": (
            "Regex.IsMatch() valida el input contra una expresión regular. "
            "Es un sanitizador poderoso cuando se usa con WHITELIST (solo permite "
            "caracteres seguros conocidos). "
            "Con blacklist es frágil y el taint no debe eliminarse completamente. "
            "Patrón seguro (whitelist de alfanumérico): "
            "if (!Regex.IsMatch(input, @'^[a-zA-Z0-9 _.-]+$')) return BadRequest();"
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "regex", "pattern", "conditional"],
    },
    {
        "id":              "SAN-VAL-024",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.RegularExpressions.Regex.Match",
        "name":            "Regex.Match — extracción con patrón de validación",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION", "XSS"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument", "html_body"],
        "confidence":      0.65,
        "limitations": (
            "Confidence 0.65 — Regex.Match extrae partes del input. "
            "El Match.Value resultante puede ser más seguro que el input original "
            "si el patrón es restrictivo, pero el taint_analyzer debe rastrear "
            "qué parte se usa (el string completo vs el grupo capturado)."
        ),
        "description": (
            "Regex.Match() extrae la primera coincidencia del patrón. "
            "Si el patrón es una whitelist estricta, el Match.Value es más seguro. "
            "Confianza menor que IsMatch porque requiere análisis del patrón y del uso."
        ),
        "frameworks":      ["generic"],
        "tags":            ["validation", "regex", "match", "extract", "partial"],
    },

    # =========================================================================
    #  SECCIÓN 8: DATA ANNOTATIONS — validación declarativa en modelos
    # =========================================================================

    {
        "id":              "SAN-VAL-025",
        "rule_type":       "sanitizer",
        "symbol":          "System.ComponentModel.DataAnnotations.Validator.TryValidateObject",
        "name":            "Validator.TryValidateObject — validación de modelo completo",
        "sanitizes":       ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "html_body", "command_argument"],
        "confidence":      0.75,
        "limitations": (
            "Confidence 0.75 — la efectividad depende de los DataAnnotations definidos. "
            "Sin atributos de validación, no sanitiza nada. "
            "Con [StringLength], [RegularExpression] con whitelist, [Range] → efectivo. "
            "Con [Required] solo → no sanitiza contra injection. "
            "No reemplaza validación explícita en sinks críticos."
        ),
        "description": (
            "Validator.TryValidateObject() ejecuta todos los DataAnnotations del modelo: "
            "[Required], [StringLength], [RegularExpression], [Range], [EmailAddress], etc. "
            "En ASP.NET Core con [ApiController], ModelState.IsValid hace esto automáticamente. "
            "Sanitizador de nivel de modelo — complementa, no reemplaza, validación en sinks."
        ),
        "frameworks":      ["aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "data-annotations", "model", "mvc"],
    },
    {
        "id":              "SAN-VAL-026",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.AspNetCore.Mvc.ControllerBase.ModelState",
        "name":            "ModelState.IsValid — validación automática de modelo en ASP.NET Core",
        "sanitizes":       ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "html_body", "command_argument"],
        "confidence":      0.75,
        "limitations": (
            "Mismas limitaciones que Validator.TryValidateObject. "
            "Con [ApiController] se ejecuta automáticamente y retorna 400 "
            "si ModelState.IsValid es false. "
            "La protección real depende de los atributos en el modelo."
        ),
        "description": (
            "ModelState.IsValid verifica que el modelo de request "
            "cumple todos los DataAnnotations definidos. "
            "Con [ApiController] en ASP.NET Core, la validación es automática "
            "y el action method no se ejecuta si ModelState.IsValid es false."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["validation", "modelstate", "mvc", "automatic"],
    },

    # =========================================================================
    #  SECCIÓN 9: VALIDACIÓN DE EMAIL, TELÉFONO Y FORMATOS ESPECÍFICOS
    # =========================================================================

    {
        "id":              "SAN-VAL-027",
        "rule_type":       "sanitizer",
        "symbol":          "System.ComponentModel.DataAnnotations.EmailAddressAttribute",
        "name":            "[EmailAddress] — validación de formato de email",
        "sanitizes":       ["SQL_INJECTION", "XSS", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "html_body", "log_entry"],
        "confidence":      0.80,
        "limitations": (
            "Confidence 0.80 — un email válido no puede contener la mayoría de inyecciones, "
            "pero los emails pueden contener caracteres como +, ., - y comillas simples "
            "que en algunos contextos pueden ser peligrosos. "
            "Para SQL usar parameterización adicional."
        ),
        "description": (
            "EmailAddressAttribute valida que el string tiene formato de email. "
            "Un email válido tiene limitaciones de caracteres que reducen el riesgo "
            "de injection. Complementar con parameterización para SQL."
        ),
        "frameworks":      ["aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "email", "format", "data-annotation"],
    },
    {
        "id":              "SAN-VAL-028",
        "rule_type":       "sanitizer",
        "symbol":          "System.ComponentModel.DataAnnotations.RangeAttribute",
        "name":            "[Range] — validación de rango numérico",
        "sanitizes":       ["SQL_INJECTION", "COMMAND_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "command_argument"],
        "confidence":      0.88,
        "limitations": (
            "Confidence 0.88 — Range valida que el valor está dentro del rango [min, max]. "
            "Para valores numéricos es muy seguro. "
            "Para strings (StringLength) no previene injection — solo limita longitud."
        ),
        "description": (
            "[Range(min, max)] valida que el valor está dentro del rango especificado. "
            "Para atributos numéricos es un sanitizador efectivo para injection. "
            "Ejemplo: [Range(1, 1000000)] garantiza un int positivo en rango."
        ),
        "frameworks":      ["aspnetcore", "aspnet_mvc"],
        "tags":            ["validation", "range", "numeric", "data-annotation"],
    },

    # =========================================================================
    #  SECCIÓN 10: VALIDACIÓN ESPECÍFICA DE SEGURIDAD
    # =========================================================================

    {
        "id":              "SAN-VAL-029",
        "rule_type":       "sanitizer",
        "symbol":          "System.Web.Mvc.ValidateInputAttribute",
        "name":            "[ValidateInput(true)] — reactivación de validación HTML (ASP.NET MVC)",
        "sanitizes":       ["XSS", "RAZOR_XSS"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["html_body"],
        "confidence":      0.82,
        "limitations": (
            "Confidence 0.82 — solo disponible en ASP.NET MVC clásico. "
            "ValidateInput=true (default) activa la validación de request de ASP.NET "
            "que rechaza HTML peligroso. "
            "ValidateInput=false DESACTIVA la protección → es un SINK, no un sanitizador. "
            "No equivale a sanitización completa — prefiere encoding explícito."
        ),
        "description": (
            "[ValidateInput(true)] en ASP.NET MVC clásico reactiva la validación "
            "de HTML/script en requests que fue desactivada con [ValidateInput(false)]. "
            "Requiere que un action method que usa [ValidateInput(false)] más arriba "
            "en la jerarquía lo reactive."
        ),
        "frameworks":      ["aspnet_mvc"],
        "tags":            ["validation", "aspnet-mvc", "html-validation", "request"],
    },
    {
        "id":              "SAN-VAL-030",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.AspNetCore.Antiforgery.IAntiforgery.ValidateRequestAsync",
        "name":            "IAntiforgery.ValidateRequestAsync — validación de token CSRF",
        "sanitizes":       ["CSRF"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["csrf_token"],
        "confidence":      0.96,
        "limitations": (
            "Solo previene CSRF — no protege contra otras injection. "
            "La confianza depende de la longitud y aleatoriedad del token."
        ),
        "description": (
            "IAntiforgery.ValidateRequestAsync() valida el token anti-CSRF de ASP.NET Core. "
            "Equivalente a [ValidateAntiForgeryToken] pero programático. "
            "Previene CSRF attacks — el token es único por sesión y verificado en el servidor."
        ),
        "frameworks":      ["aspnetcore"],
        "tags":            ["validation", "csrf", "antiforgery", "security"],
    },
    {
        "id":              "SAN-VAL-031",
        "rule_type":       "sanitizer",
        "symbol":          "System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateToken",
        "name":            "JwtSecurityTokenHandler.ValidateToken — validación de JWT",
        "sanitizes":       ["SQL_INJECTION", "XSS"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "html_body"],
        "confidence":      0.78,
        "limitations": (
            "Confidence 0.78 — ValidateToken verifica firma y claims del JWT. "
            "Los claims validados son más confiables que claims sin validar. "
            "Pero los valores de los claims (strings) pueden contener "
            "caracteres peligrosos — aún se necesita sanitización del valor."
        ),
        "description": (
            "JwtSecurityTokenHandler.ValidateToken() valida la firma y expiración del JWT. "
            "Los claims resultantes son de un JWT válido (firmado), "
            "pero el contenido del claim sigue requiriendo sanitización."
        ),
        "frameworks":      ["aspnetcore", "generic"],
        "tags":            ["validation", "jwt", "token", "auth", "claims"],
    },

    # =========================================================================
    #  SECCIÓN 11: VALIDACIÓN DE IPAddress Y NETWORKING
    # =========================================================================

    {
        "id":              "SAN-VAL-032",
        "rule_type":       "sanitizer",
        "symbol":          "System.Net.IPAddress.TryParse",
        "name":            "IPAddress.TryParse — validación de dirección IP",
        "sanitizes":       ["COMMAND_INJECTION", "SQL_INJECTION", "LOG_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["command_argument", "sql_query", "log_entry"],
        "confidence":      0.93,
        "limitations": (
            "Confidence 0.93 — una IP válida no puede contener injection. "
            "NO previene SSRF — una IP privada es válida (127.0.0.1, 10.0.0.1). "
            "Para SSRF usar whitelist de IPs/rangos permitidos adicionalmente."
        ),
        "description": (
            "IPAddress.TryParse() valida que el string es una dirección IP válida "
            "(IPv4 o IPv6). Una IP válida no puede contener injection de strings. "
            "Útil para validar IPs en configuraciones, logs y comandos de red."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "network", "ip", "ipaddress", "parse"],
    },

    # =========================================================================
    #  SECCIÓN 12: FLUENT VALIDATION — librería de validación popular
    # =========================================================================

    {
        "id":              "SAN-VAL-033",
        "rule_type":       "sanitizer",
        "symbol":          "FluentValidation.AbstractValidator.Validate",
        "name":            "FluentValidation AbstractValidator.Validate — validación fluent",
        "sanitizes":       ["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "html_body", "command_argument", "file_path"],
        "confidence":      0.75,
        "limitations": (
            "Confidence 0.75 — la efectividad depende completamente de las reglas "
            "definidas en el AbstractValidator<T>. "
            "Sin reglas de whitelist/formato → no sanitiza. "
            "Con .Must(s => allowedValues.Contains(s)) o .Matches(whitlistRegex) → efectivo."
        ),
        "description": (
            "FluentValidation AbstractValidator.Validate() ejecuta las reglas "
            "de validación definidas en el validator. "
            "Es un sanitizador poderoso y legible cuando se usan reglas de whitelist. "
            "Permite validación compleja y reutilizable para modelos de dominio."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "fluentvalidation", "library", "model"],
    },
    {
        "id":              "SAN-VAL-034",
        "rule_type":       "sanitizer",
        "symbol":          "FluentValidation.AbstractValidator.ValidateAsync",
        "name":            "FluentValidation AbstractValidator.ValidateAsync — validación asíncrona",
        "sanitizes":       ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"],
        "sanitizer_type":  "VALIDATION",
        "encoding_context": ["sql_query", "html_body", "command_argument"],
        "confidence":      0.75,
        "limitations":     "Mismas limitaciones que Validate(). Versión asíncrona.",
        "description": (
            "FluentValidation ValidateAsync() — versión asíncrona del validator. "
            "Mismo nivel de sanitización que Validate()."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["validation", "fluentvalidation", "async", "library"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCIONES DE ACCESO AL CATÁLOGO
# ─────────────────────────────────────────────────────────────────────────────

def get_validation_sanitizer_rules() -> list[dict]:
    """Retorna el catálogo completo de sanitizadores de validación."""
    return VALIDATION_SANITIZERS


def get_validation_sanitizer_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in VALIDATION_SANITIZERS}


def get_sanitizers_for_vulnerability(vulnerability: str) -> list[dict]:
    """
    Retorna los sanitizadores de validación que neutralizan
    un tipo específico de vulnerabilidad.
    Args:
        vulnerability: e.g. "SQL_INJECTION", "XSS", "PATH_TRAVERSAL"
    """
    return [
        r for r in VALIDATION_SANITIZERS
        if vulnerability in r.get("sanitizes", [])
    ]


def get_type_conversion_sanitizers() -> list[dict]:
    """
    Retorna sanitizadores de conversión de tipo (TryParse, Guid.TryParse, etc.).
    Son los más fuertes — el tipo resultante garantiza ausencia de injection.
    """
    type_tags = {"integer", "long", "guid", "uuid", "double", "decimal",
                 "boolean", "datetime", "datetimeoffset", "timespan", "ipaddress"}
    return [
        r for r in VALIDATION_SANITIZERS
        if type_tags & set(r.get("tags", []))
    ]


def get_path_validation_sanitizers() -> list[dict]:
    """Retorna sanitizadores específicos para validación de rutas de archivo."""
    return [
        r for r in VALIDATION_SANITIZERS
        if "PATH_TRAVERSAL" in r.get("sanitizes", [])
    ]


def get_url_validation_sanitizers() -> list[dict]:
    """Retorna sanitizadores para validación de URLs (SSRF, Open Redirect)."""
    return [
        r for r in VALIDATION_SANITIZERS
        if any(v in r.get("sanitizes", [])
               for v in ("SSRF", "OPEN_REDIRECT"))
    ]


def get_high_confidence_sanitizers(min_confidence: float = 0.90) -> list[dict]:
    """Retorna sanitizadores con confianza >= min_confidence."""
    return [
        r for r in VALIDATION_SANITIZERS
        if r.get("confidence", 0.0) >= min_confidence
    ]


def get_sanitizer_confidence_map() -> dict[str, float]:
    """
    Retorna mapa {symbol_prefix: confidence} para el TaintAnalyzer.
    Usado para determinar si el taint debe detenerse completamente
    o solo reducirse (confianza parcial).
    """
    return {
        rule["symbol"]: rule.get("confidence", 0.0)
        for rule in VALIDATION_SANITIZERS
    }


def get_sanitizes_vulnerabilities_map() -> dict[str, list[str]]:
    """
    Retorna mapa {symbol_prefix: [vulnerability_kinds]} para matching
    rápido en el TaintAnalyzer.
    """
    return {
        rule["symbol"]: rule.get("sanitizes", [])
        for rule in VALIDATION_SANITIZERS
    }