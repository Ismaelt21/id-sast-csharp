# =============================================================================
#  csharp-sast / core / rules / sinks / path_sinks.py
# =============================================================================
#
#  CATÁLOGO DE SINKS DE PATH TRAVERSAL PARA C#
#  ─────────────────────────────────────────────
#  Cubre: System.IO.File, System.IO.Directory, System.IO.Path,
#  FileStream, StreamReader, StreamWriter, System.IO.Compression,
#  IWebHostEnvironment/IHostingEnvironment y acceso a recursos web.
#
#  QUÉ ES PATH TRAVERSAL EN .NET:
#    El atacante controla (total o parcialmente) la ruta de un archivo
#    o directorio que la aplicación abre, lee, escribe o elimina.
#    Usando secuencias como "../" puede salir del directorio permitido
#    y acceder a archivos del sistema operativo.
#
#  EJEMPLOS DE IMPACTO:
#    Lectura:    GET /download?file=../../../../etc/passwd
#    Escritura:  POST /upload?path=../../web.config  (reemplaza config)
#    Eliminación: DELETE /file?name=../../cron/job   (borra scripts del sistema)
#    RCE:        Escritura en directorio web → upload de shell .aspx
#
#  PATRONES ESPECÍFICOS DE C#:
#    • Path.Combine("uploads", userInput) — NO es seguro si userInput
#      comienza con "/" o "C:\" en Windows puede salir del directorio
#    • Path.GetFileName() solo elimina dirs del nombre, no es suficiente
#    • En Windows: UNC paths (\\server\share), device paths (\\.\)
#      pueden bypassear validaciones de Path.GetFullPath()
#
# =============================================================================

from __future__ import annotations

PATH_TRAVERSAL_SINKS: list[dict] = [

    # =========================================================================
    #  System.IO.File — operaciones sobre archivos individuales
    # =========================================================================

    {
        "id":              "PATH-001",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.ReadAllText",
        "name":            "File.ReadAllText con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "File.ReadAllText con ruta controlada por el usuario permite leer "
            "archivos arbitrarios del servidor usando path traversal (../). "
            "Puede exponer: web.config, appsettings.json, /etc/passwd, "
            "código fuente, certificados privados, etc."
        ),
        "remediation": (
            "1. Extraer solo el nombre: var safeName = Path.GetFileName(userInput); "
            "2. Combinar con directorio fijo: var safePath = Path.Combine(baseDir, safeName); "
            "3. Resolver y verificar: var full = Path.GetFullPath(safePath); "
            "   if (!full.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase)) throw new SecurityException();"
        ),
        "safe_alternative": "Path.GetFileName() + Path.GetFullPath() + validación de directorio base",
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["path", "traversal", "lfi", "file", "read", "owasp-a01"],
    },
    {
        "id":              "PATH-002",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.ReadAllLines",
        "name":            "File.ReadAllLines con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.ReadAllLines lee archivo línea a línea — mismo riesgo de path traversal que ReadAllText.",
        "remediation":     "Validar la ruta con Path.GetFullPath() y verificar contra directorio base.",
        "safe_alternative": "Path.GetFileName() + directorio base fijo",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["path", "traversal", "file", "read"],
    },
    {
        "id":              "PATH-003",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.ReadAllBytes",
        "name":            "File.ReadAllBytes con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.ReadAllBytes lee el contenido binario completo — permite exfiltrar archivos binarios (binarios, certificados .pfx).",
        "remediation":     "Validar ruta contra directorio base.",
        "safe_alternative": "Validación de ruta + directorio base",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["path", "traversal", "file", "binary"],
    },
    {
        "id":              "PATH-004",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.WriteAllText",
        "name":            "File.WriteAllText con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "File.WriteAllText con ruta dinámica permite escribir/sobreescribir "
            "archivos arbitrarios. Puede resultar en: "
            "sobreescritura de web.config (RCE), escritura de shells .aspx, "
            "corrupción de archivos del sistema."
        ),
        "remediation":     "Validar y restringir la ruta a un directorio de escritura permitido.",
        "safe_alternative": "Path.GetFileName() + directorio de escritura fijo + validación",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["path", "traversal", "file", "write"],
    },
    {
        "id":              "PATH-005",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.WriteAllLines",
        "name":            "File.WriteAllLines con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.WriteAllLines escribe líneas a archivo con ruta dinámica — mismo riesgo que WriteAllText.",
        "remediation":     "Validar ruta contra directorio de escritura permitido.",
        "safe_alternative": "Directorio de escritura fijo + validación",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "write"],
    },
    {
        "id":              "PATH-006",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.WriteAllBytes",
        "name":            "File.WriteAllBytes con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.WriteAllBytes escribe contenido binario — riesgo de escritura de ejecutables o scripts.",
        "remediation":     "Validar ruta y tipo de archivo permitido.",
        "safe_alternative": "Directorio de escritura fijo + whitelist de extensiones",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "binary", "write"],
    },
    {
        "id":              "PATH-007",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.Open",
        "name":            "File.Open con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.Open abre un FileStream en la ruta especificada — vulnerable a path traversal en lectura o escritura.",
        "remediation":     "Validar la ruta con Path.GetFullPath() y comparar con el directorio base.",
        "safe_alternative": "Path.GetFullPath() + directorio base fijo",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file"],
    },
    {
        "id":              "PATH-008",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.Create",
        "name":            "File.Create con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.Create crea o trunca un archivo en la ruta especificada — permite crear archivos en ubicaciones arbitrarias.",
        "remediation":     "Validar la ruta. Verificar directorio base y extensión de archivo.",
        "safe_alternative": "Directorio de creación fijo + validación de extensión",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "create"],
    },
    {
        "id":              "PATH-009",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.Delete",
        "name":            "File.Delete con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.Delete con ruta dinámica puede eliminar archivos arbitrarios del servidor.",
        "remediation":     "Validar estrictamente la ruta antes de eliminar. Verificar que esté en el directorio permitido.",
        "safe_alternative": "Validación de ruta + directorio base",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "delete"],
    },
    {
        "id":              "PATH-010",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.Move",
        "name":            "File.Move con rutas dinámicas",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0, 1],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.Move mueve un archivo de origen a destino. Con rutas dinámicas permite mover archivos a/desde ubicaciones arbitrarias.",
        "remediation":     "Validar ambas rutas (origen y destino) contra sus directorios base respectivos.",
        "safe_alternative": "Validación de ambas rutas",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "move"],
    },
    {
        "id":              "PATH-011",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.Copy",
        "name":            "File.Copy con rutas dinámicas",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0, 1],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.Copy con rutas dinámicas — lectura desde origen arbitrario y/o escritura en destino arbitrario.",
        "remediation":     "Validar ambas rutas. El destino especialmente crítico para evitar sobreescritura de archivos sensibles.",
        "safe_alternative": "Validación de ambas rutas",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "copy"],
    },
    {
        "id":              "PATH-012",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.AppendAllText",
        "name":            "File.AppendAllText con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "File.AppendAllText añade texto a un archivo existente — permite inyectar contenido en archivos del sistema (logs, configs).",
        "remediation":     "Validar ruta. Especialmente peligroso en logs — usar un logger estructurado en su lugar.",
        "safe_alternative": "Directorio de escritura fijo + ILogger",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "file", "append"],
    },
    {
        "id":              "PATH-013",
        "rule_type":       "sink",
        "symbol":          "System.IO.File.Exists",
        "name":            "File.Exists con ruta dinámica (enumeración)",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "LOW",
        "cwe":             "CWE-22",
        "cvss_base":       3.7,
        "description": (
            "File.Exists con ruta dinámica permite enumeración de archivos — "
            "el atacante puede determinar si ciertos archivos existen en el servidor. "
            "Menor severidad que lectura, pero permite fingerprinting del sistema."
        ),
        "remediation":     "Restringir a directorio base. No revelar existencia de archivos fuera del área pública.",
        "safe_alternative": "Verificar existencia solo dentro del directorio base permitido",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "enumeration", "information-disclosure"],
    },

    # =========================================================================
    #  System.IO.FileStream y streams relacionados
    # =========================================================================

    {
        "id":              "PATH-014",
        "rule_type":       "sink",
        "symbol":          "System.IO.FileStream..ctor",
        "name":            "FileStream con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "Constructor de FileStream con ruta dinámica. "
            "El modo (FileMode) determina si es lectura, escritura o ambas — "
            "con FileMode.OpenOrCreate y ruta arbitraria puede crear archivos en cualquier ubicación."
        ),
        "remediation":     "Validar y normalizar la ruta antes de abrir el stream.",
        "safe_alternative": "Path.GetFullPath() + directorio base",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["path", "traversal", "stream", "file"],
    },
    {
        "id":              "PATH-015",
        "rule_type":       "sink",
        "symbol":          "System.IO.StreamReader..ctor",
        "name":            "StreamReader con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "StreamReader construido con ruta dinámica para leer archivos de texto.",
        "remediation":     "Validar la ruta antes de crear el StreamReader.",
        "safe_alternative": "Path.GetFullPath() + validación de directorio base",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "stream", "read"],
    },
    {
        "id":              "PATH-016",
        "rule_type":       "sink",
        "symbol":          "System.IO.StreamWriter..ctor",
        "name":            "StreamWriter con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "StreamWriter con ruta dinámica para escribir archivos de texto.",
        "remediation":     "Validar la ruta contra directorio de escritura permitido.",
        "safe_alternative": "Directorio de escritura fijo + validación",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "stream", "write"],
    },
    {
        "id":              "PATH-017",
        "rule_type":       "sink",
        "symbol":          "System.IO.BinaryReader..ctor",
        "name":            "BinaryReader con ruta dinámica (vía FileStream)",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "BinaryReader con FileStream de ruta dinámica — lectura binaria de archivos arbitrarios.",
        "remediation":     "Validar la ruta del FileStream subyacente.",
        "safe_alternative": "FileStream con ruta validada",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "binary", "read"],
    },
    {
        "id":              "PATH-018",
        "rule_type":       "sink",
        "symbol":          "System.IO.BinaryWriter..ctor",
        "name":            "BinaryWriter con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "BinaryWriter con FileStream de ruta dinámica — escritura binaria en archivos arbitrarios.",
        "remediation":     "Validar la ruta del FileStream subyacente.",
        "safe_alternative": "FileStream con ruta validada",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "binary", "write"],
    },

    # =========================================================================
    #  System.IO.Directory — operaciones sobre directorios
    # =========================================================================

    {
        "id":              "PATH-019",
        "rule_type":       "sink",
        "symbol":          "System.IO.Directory.GetFiles",
        "name":            "Directory.GetFiles con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "MEDIUM",
        "cwe":             "CWE-22",
        "cvss_base":       5.3,
        "description": (
            "Directory.GetFiles con directorio dinámico puede exponer listados "
            "de directorios arbitrarios del servidor, revelando estructura de archivos."
        ),
        "remediation":     "Restringir a un directorio base confiable. Nunca listar directorios del sistema.",
        "safe_alternative": "Directorio base fijo + validación",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "directory", "listing"],
    },
    {
        "id":              "PATH-020",
        "rule_type":       "sink",
        "symbol":          "System.IO.Directory.GetDirectories",
        "name":            "Directory.GetDirectories con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "MEDIUM",
        "cwe":             "CWE-22",
        "cvss_base":       5.3,
        "description":     "Directory.GetDirectories con directorio dinámico — enumeración de subdirectorios arbitrarios.",
        "remediation":     "Restringir a directorio base permitido.",
        "safe_alternative": "Directorio base fijo",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "directory", "listing"],
    },
    {
        "id":              "PATH-021",
        "rule_type":       "sink",
        "symbol":          "System.IO.Directory.CreateDirectory",
        "name":            "Directory.CreateDirectory con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "MEDIUM",
        "cwe":             "CWE-22",
        "cvss_base":       5.3,
        "description":     "Directory.CreateDirectory con ruta dinámica puede crear directorios en ubicaciones arbitrarias.",
        "remediation":     "Restringir a un directorio base de creación permitido.",
        "safe_alternative": "Directorio base fijo + validación",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "directory", "create"],
    },
    {
        "id":              "PATH-022",
        "rule_type":       "sink",
        "symbol":          "System.IO.Directory.Delete",
        "name":            "Directory.Delete con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description":     "Directory.Delete con ruta dinámica puede eliminar directorios arbitrarios. Con recursive=true → destructivo.",
        "remediation":     "Validar estrictamente la ruta. Nunca permitir eliminación recursiva de rutas del usuario.",
        "safe_alternative": "Validación estricta de ruta + directorio base",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "directory", "delete"],
    },
    {
        "id":              "PATH-023",
        "rule_type":       "sink",
        "symbol":          "System.IO.Directory.EnumerateFiles",
        "name":            "Directory.EnumerateFiles con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "MEDIUM",
        "cwe":             "CWE-22",
        "cvss_base":       5.3,
        "description":     "Directory.EnumerateFiles con directorio dinámico — enumeración lazy de archivos arbitrarios.",
        "remediation":     "Restringir a directorio base permitido.",
        "safe_alternative": "Directorio base fijo",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "directory", "enumerate"],
    },

    # =========================================================================
    #  System.IO.Path — manipulación de rutas
    # =========================================================================

    {
        "id":              "PATH-024",
        "rule_type":       "sink",
        "symbol":          "System.IO.Path.Combine",
        "name":            "Path.Combine con componente dinámico",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [1],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "MEDIUM",
        "cwe":             "CWE-22",
        "cvss_base":       5.3,
        "description": (
            "Path.Combine NO es seguro contra path traversal si el componente "
            "dinámico contiene un path absoluto o '../'. "
            "Path.Combine('uploads', '/etc/passwd') retorna '/etc/passwd' en .NET. "
            "Path.Combine('uploads', '../secret') retorna 'uploads/../secret'."
        ),
        "remediation": (
            "Después de Path.Combine, aplicar Path.GetFullPath() y verificar "
            "que el resultado comience con el directorio base: "
            "var full = Path.GetFullPath(Path.Combine(baseDir, userInput)); "
            "if (!full.StartsWith(baseDir)) throw new SecurityException();"
        ),
        "safe_alternative": "Path.Combine + Path.GetFullPath() + validación de directorio base",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["path", "traversal", "combine", "tricky"],
    },

    # =========================================================================
    #  System.IO.Compression — archivos ZIP y similares (Zip Slip)
    # =========================================================================

    {
        "id":              "PATH-025",
        "rule_type":       "sink",
        "symbol":          "System.IO.Compression.ZipFile.ExtractToDirectory",
        "name":            "ZipFile.ExtractToDirectory — Zip Slip potencial",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "ZipFile.ExtractToDirectory con archivo ZIP del usuario puede resultar "
            "en 'Zip Slip': si el ZIP contiene entradas con rutas relativas como "
            "'../../../../etc/cron/malicious', se extraen fuera del directorio destino. "
            ".NET 5+ tiene protección por defecto, pero versiones anteriores son vulnerables."
        ),
        "remediation": (
            "Verificar cada entrada del ZIP antes de extraer: "
            "var destPath = Path.GetFullPath(Path.Combine(destDir, entry.FullName)); "
            "if (!destPath.StartsWith(destDir)) throw new SecurityException('Zip Slip'); "
            "Nunca usar ZipFile.ExtractToDirectory con ZIPs de fuentes no confiables en .NET < 5."
        ),
        "safe_alternative": "Extracción manual con validación de cada entrada",
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["path", "traversal", "zip", "zip-slip", "archive"],
    },
    {
        "id":              "PATH-026",
        "rule_type":       "sink",
        "symbol":          "System.IO.Compression.ZipArchiveEntry.ExtractToFile",
        "name":            "ZipArchiveEntry.ExtractToFile — Zip Slip potencial",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [1],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "ExtractToFile extrae una entrada ZIP a la ruta especificada. "
            "Si el nombre de la entrada contiene '../', la ruta destino puede salir del directorio. "
            "El segundo argumento (destinationFileName) también puede ser dinámico."
        ),
        "remediation": (
            "Validar que destinationFileName esté dentro del directorio destino: "
            "var full = Path.GetFullPath(destinationFileName); "
            "if (!full.StartsWith(allowedDir)) throw new SecurityException();"
        ),
        "safe_alternative": "Validación de ruta de extracción antes de ExtractToFile",
        "frameworks":      ["generic"],
        "tags":            ["path", "traversal", "zip", "zip-slip"],
    },

    # =========================================================================
    #  ASP.NET Core — acceso a archivos web
    # =========================================================================

    {
        "id":              "PATH-027",
        "rule_type":       "sink",
        "symbol":          "Microsoft.AspNetCore.StaticFiles.StaticFileMiddleware",
        "name":            "StaticFileMiddleware con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "low",
        "severity":        "MEDIUM",
        "cwe":             "CWE-22",
        "cvss_base":       5.3,
        "description": (
            "Si la ruta raíz del StaticFileMiddleware se configura dinámicamente "
            "o si se añaden rutas del usuario al request path, puede exponer "
            "archivos fuera del wwwroot."
        ),
        "remediation":     "Hardcodear la ruta raíz de archivos estáticos. Nunca añadir input del usuario al path de request.",
        "safe_alternative": "StaticFileMiddleware con WebRootPath fijo",
        "frameworks":      ["aspnetcore"],
        "tags":            ["path", "traversal", "aspnetcore", "static"],
    },
    {
        "id":              "PATH-028",
        "rule_type":       "sink",
        "symbol":          "Microsoft.AspNetCore.Hosting.IWebHostEnvironment.ContentRootPath",
        "name":            "ContentRootPath + input del usuario",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "medium",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "Combinar ContentRootPath o WebRootPath con input del usuario para "
            "construir una ruta de archivo. ContentRootPath es el directorio del proyecto, "
            "no un directorio público — un path traversal aquí expone el código fuente."
        ),
        "remediation":     "Usar Path.GetFullPath() y verificar que la ruta resultante esté dentro del WebRootPath.",
        "safe_alternative": "WebRootPath + Path.GetFileName(userInput) + validación",
        "frameworks":      ["aspnetcore"],
        "tags":            ["path", "traversal", "aspnetcore", "webroot"],
    },

    # =========================================================================
    #  IFormFile — subida de archivos en ASP.NET Core
    # =========================================================================

    {
        "id":              "PATH-029",
        "rule_type":       "sink",
        "symbol":          "Microsoft.AspNetCore.Http.IFormFile.CopyToAsync",
        "name":            "IFormFile.CopyToAsync con ruta dinámica",
        "vulnerability":   "PATH_TRAVERSAL",
        "tainted_args":    [0],
        "always_vulnerable": False,
        "confidence":      "high",
        "severity":        "HIGH",
        "cwe":             "CWE-22",
        "cvss_base":       7.5,
        "description": (
            "Al copiar un archivo subido (IFormFile) a una ruta construida desde "
            "IFormFile.FileName (controlado por el cliente), hay riesgo de path traversal. "
            "Nunca usar IFormFile.FileName directamente como nombre de archivo en el servidor."
        ),
        "remediation": (
            "Usar Path.GetFileName(file.FileName) para limpiar el nombre. "
            "Generar un nombre de archivo único (Guid.NewGuid()) en el servidor. "
            "Guardar en un directorio fijo de uploads. "
            "Validar extensión y tipo MIME del archivo."
        ),
        "safe_alternative": "Guid.NewGuid().ToString() + extensión validada como nombre de archivo",
        "frameworks":      ["aspnetcore"],
        "tags":            ["path", "traversal", "upload", "formfile", "aspnetcore"],
    },
]


def get_path_sink_rules() -> list[dict]:
    """Retorna el catálogo completo de reglas de Path Traversal."""
    return PATH_TRAVERSAL_SINKS


def get_path_sink_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in PATH_TRAVERSAL_SINKS}


def get_path_sinks_by_framework(framework: str) -> list[dict]:
    """Retorna las reglas aplicables a un framework específico."""
    return [r for r in PATH_TRAVERSAL_SINKS if framework in r.get("frameworks", [])]


def get_path_sinks_by_severity(severity: str) -> list[dict]:
    """Retorna los sinks de una severidad específica."""
    return [r for r in PATH_TRAVERSAL_SINKS if r.get("severity", "") == severity.upper()]


def get_write_sinks() -> list[dict]:
    """Retorna solo los sinks de escritura (mayor riesgo: RCE via shell upload)."""
    write_tags = {"write", "append", "create", "upload"}
    return [
        r for r in PATH_TRAVERSAL_SINKS
        if write_tags & set(r.get("tags", []))
    ]