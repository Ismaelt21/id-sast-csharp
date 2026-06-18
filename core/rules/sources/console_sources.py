# =============================================================================
#  csharp-sast / core / rules / sources / console_sources.py
# =============================================================================
#
#  FUENTES DE INPUT PARA APLICACIONES DE CONSOLA, CLI, SERVICIOS Y RED
#  ─────────────────────────────────────────────────────────────────────
#
#  COBERTURA DE ESTE MÓDULO:
#    1. Console / stdin       — Console.ReadLine(), Console.In, args[]
#    2. Argumentos CLI        — Environment.GetCommandLineArgs(), args en Main()
#    3. Variables de entorno  — Environment.GetEnvironmentVariable()
#    4. Archivos de config    — cuando se leen de fuentes externas no confiables
#    5. Streams de red        — TcpClient, UdpClient, NetworkStream
#    6. Named Pipes           — PipeStream para IPC
#    7. Sockets               — Socket de bajo nivel
#    8. Base de datos         — resultados de DB como fuente (second-order injection)
#    9. Servicios externos    — datos de APIs externas (third-party)
#    10. Archivos del sistema — lectura de archivos como fuente de datos externos
#    11. Registro de Windows  — RegistryKey (valores del registro)
#    12. Servicios de mensajería — MSMQ, RabbitMQ, Azure Service Bus
#    13. gRPC                 — parámetros de llamadas gRPC
#
#  CONCEPTOS CLAVE:
#
#  SECOND-ORDER INJECTION:
#    Se produce cuando datos tainted se almacenan primero en la base de datos
#    (limpiados superficialmente o escapados para el almacenamiento)
#    y luego se recuperan y usan sin re-sanitización en un contexto diferente.
#    Ejemplo:
#      1. Usuario envía: name = "'; DROP TABLE users;--"
#      2. Se almacena en BD (con escape para el INSERT)
#      3. Se recupera para construir otra query: SELECT * WHERE name='{stored_value}'
#      4. El valor almacenado es la fuente de la segunda inyección
#    Los resultados de DB se marcan como STORED_INPUT (no USER_INPUT directo)
#    con severity_multiplier reducido pero no nulo.
#
#  LABELS DE TAINT:
#    USER_INPUT       → controlado directamente por el usuario (stdin, args)
#    EXTERNAL_INPUT   → datos de fuentes externas (APIs, archivos, env vars)
#    NETWORK_INPUT    → datos crudos de red (sockets, streams TCP/UDP)
#    STORED_INPUT     → datos almacenados previamente (BD, archivos de config)
#                       riesgo de second-order injection
#    ENVIRONMENT_INPUT → variables de entorno y configuración del proceso
#
#  ALINEACIÓN CON aspnet_sources.py Y wcf_sources.py:
#    Mismos campos, misma convención de naming, misma estructura de dict.
#    Campos: id, rule_type, symbol, name, taint_label, severity_multiplier,
#            implicit, data_format, authentication_context, description,
#            frameworks, tags
#
# =============================================================================

from __future__ import annotations

CONSOLE_AND_GENERAL_SOURCES: list[dict] = [

    # =========================================================================
    #  SECCIÓN 1: CONSOLE / STDIN
    #  Aplicaciones de consola, herramientas CLI, scripts de automatización.
    #  El usuario que ejecuta el programa controla el input.
    # =========================================================================

    {
        "id":                    "SRC-CON-001",
        "rule_type":             "source",
        "symbol":                "System.Console.ReadLine",
        "name":                  "Console.ReadLine() — input de consola",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Console.ReadLine() lee una línea de texto de la entrada estándar (stdin). "
            "En aplicaciones de consola y herramientas CLI es el vector "
            "más directo de input del usuario. "
            "Si el valor se usa en queries SQL, comandos del sistema o rutas "
            "de archivo sin validación → vulnerable a injection."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["console", "stdin", "cli", "user-input", "interactive"],
    },
    {
        "id":                    "SRC-CON-002",
        "rule_type":             "source",
        "symbol":                "System.Console.Read",
        "name":                  "Console.Read() — input de consola (carácter individual)",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Console.Read() lee un único carácter de stdin. "
            "Severity_multiplier 0.9 — un carácter individual es menos explotable "
            "que una línea completa, pero sigue siendo tainted si se acumula en un buffer."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["console", "stdin", "char", "user-input"],
    },
    {
        "id":                    "SRC-CON-003",
        "rule_type":             "source",
        "symbol":                "System.Console.ReadKey",
        "name":                  "Console.ReadKey() — tecla individual del usuario",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Console.ReadKey() captura una tecla. "
            "Severity_multiplier 0.7 — una sola tecla raramente es explotable, "
            "pero si se usa ConsoleKeyInfo.KeyChar en un buffer que luego "
            "se usa en código sensible → tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["console", "stdin", "key", "user-input"],
    },
    {
        "id":                    "SRC-CON-004",
        "rule_type":             "source",
        "symbol":                "System.Console.In",
        "name":                  "Console.In — TextReader de stdin",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "Console.In es el TextReader del stdin. "
            "Se usa cuando se quiere leer stdin como un stream o cuando "
            "se redirige stdin desde un archivo o pipe. "
            "Equivalente funcional a Console.ReadLine() para el análisis de taint."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["console", "stdin", "stream", "textreader"],
    },
    {
        "id":                    "SRC-CON-005",
        "rule_type":             "source",
        "symbol":                "System.Console.OpenStandardInput",
        "name":                  "Console.OpenStandardInput() — stream de stdin",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "Console.OpenStandardInput() retorna el stream binario de stdin. "
            "Se usa en pipes y redirecciones. "
            "Cualquier dato leído de este stream es tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["console", "stdin", "stream", "binary"],
    },

    # =========================================================================
    #  SECCIÓN 2: ARGUMENTOS DE LÍNEA DE COMANDOS
    #  El usuario que ejecuta el programa controla los argumentos.
    #  En servicios de sistema los argumentos pueden ser controlados por
    #  configuraciones o llamadas externas.
    # =========================================================================

    {
        "id":                    "SRC-CON-006",
        "rule_type":             "source",
        "symbol":                "System.Environment.GetCommandLineArgs",
        "name":                  "Environment.GetCommandLineArgs() — argumentos del proceso",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Environment.GetCommandLineArgs() retorna el array de argumentos "
            "de línea de comandos incluyendo el nombre del ejecutable [0]. "
            "En herramientas CLI los argumentos son controlados por el usuario "
            "que invoca el programa — completamente tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["cli", "args", "commandline", "user-input"],
    },
    {
        "id":                    "SRC-CON-007",
        "rule_type":             "source",
        "symbol":                "System.Environment.CommandLine",
        "name":                  "Environment.CommandLine — línea de comandos completa como string",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Environment.CommandLine retorna la línea de comandos completa como string. "
            "Si se parsea manualmente → mismo riesgo que GetCommandLineArgs."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["cli", "commandline", "string", "user-input"],
    },
    {
        "id":                    "SRC-CON-008",
        "rule_type":             "source",
        "symbol":                "System.Environment.GetCommandLineArgs",
        "name":                  "args[] en Main() — parámetros del punto de entrada",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   1.0,
        "implicit":              True,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "El parámetro args[] de Main(string[] args) contiene los argumentos "
            "de línea de comandos. Es la forma más común de recibir input en CLIs. "
            "Implicit=True porque el taint_analyzer detecta automáticamente "
            "cuando args[] se usa en el método Main."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["cli", "args", "main", "entrypoint", "user-input"],
    },

    # =========================================================================
    #  SECCIÓN 3: VARIABLES DE ENTORNO
    #  Controlables por quien ejecuta el proceso (usuario, script de CI, atacante
    #  que comprometió el entorno de ejecución).
    # =========================================================================

    {
        "id":                    "SRC-CON-009",
        "rule_type":             "source",
        "symbol":                "System.Environment.GetEnvironmentVariable",
        "name":                  "Environment.GetEnvironmentVariable() — variable de entorno",
        "taint_label":           "ENVIRONMENT_INPUT",
        "severity_multiplier":   0.75,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Variables de entorno del proceso. Controladas por quien ejecuta el proceso. "
            "Severity_multiplier 0.75 — generalmente configuradas por administradores "
            "o scripts de despliegue, pero en entornos comprometidos o con SSRF "
            "pueden ser manipuladas. "
            "Especialmente relevante en contenedores donde las variables de entorno "
            "se usan para configuración sensible (connection strings, API keys)."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["environment", "config", "env-var", "environment-input"],
    },
    {
        "id":                    "SRC-CON-010",
        "rule_type":             "source",
        "symbol":                "System.Environment.GetEnvironmentVariables",
        "name":                  "Environment.GetEnvironmentVariables() — todas las variables",
        "taint_label":           "ENVIRONMENT_INPUT",
        "severity_multiplier":   0.75,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "Retorna todas las variables de entorno como IDictionary. "
            "Si se itera y se usan los valores en código sensible → tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["environment", "config", "env-var", "dictionary"],
    },

    # =========================================================================
    #  SECCIÓN 4: STREAMS DE RED — TCP, UDP, Sockets
    #  Datos crudos de red, más peligrosos porque pueden venir de
    #  cualquier actor en la red.
    # =========================================================================

    {
        "id":                    "SRC-CON-011",
        "rule_type":             "source",
        "symbol":                "System.Net.Sockets.TcpClient",
        "name":                  "TcpClient — cliente TCP (datos de red)",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "TcpClient recibe datos de una conexión TCP. "
            "Severity_multiplier 1.1 — datos de red sin autenticación pueden "
            "provenir de cualquier actor en la red. "
            "Si se lee el NetworkStream y se parsea sin validación → vulnerable "
            "a Protocol Injection, Command Injection, SQL Injection."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["network", "tcp", "socket", "stream", "network-input"],
    },
    {
        "id":                    "SRC-CON-012",
        "rule_type":             "source",
        "symbol":                "System.Net.Sockets.TcpListener",
        "name":                  "TcpListener — servidor TCP (datos de clientes de red)",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   1.2,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "TcpListener acepta conexiones entrantes. "
            "Severity_multiplier 1.2 — un servidor TCP expuesto acepta conexiones "
            "de cualquier cliente en la red. "
            "Los datos del TcpClient obtenido via AcceptTcpClient() son tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["network", "tcp", "server", "listener", "network-input"],
    },
    {
        "id":                    "SRC-CON-013",
        "rule_type":             "source",
        "symbol":                "System.Net.Sockets.NetworkStream",
        "name":                  "NetworkStream — stream de datos de red",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "NetworkStream es el stream de un socket de red. "
            "Leer de él produce datos tainted que vienen del extremo remoto. "
            "Si se parsea como texto, XML, JSON o comandos sin validación → vulnerable."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["network", "stream", "socket", "network-input"],
    },
    {
        "id":                    "SRC-CON-014",
        "rule_type":             "source",
        "symbol":                "System.Net.Sockets.UdpClient",
        "name":                  "UdpClient — cliente UDP (datos de red sin conexión)",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   1.1,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "any",
        "description": (
            "UdpClient recibe datagramas UDP. "
            "UDP no tiene conexión ni autenticación inherente — "
            "cualquier actor en la red puede enviar paquetes. "
            "Los bytes del datagrama son completamente tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["network", "udp", "datagram", "network-input"],
    },
    {
        "id":                    "SRC-CON-015",
        "rule_type":             "source",
        "symbol":                "System.Net.Sockets.Socket.Receive",
        "name":                  "Socket.Receive() — datos de socket de bajo nivel",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   1.2,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "any",
        "description": (
            "Socket.Receive() recibe datos crudos de un socket de bajo nivel. "
            "Severity_multiplier 1.2 — el nivel más bajo de abstracción de red: "
            "sin ningún protocolo que valide o estructure los datos. "
            "Cualquier parseo manual de los bytes es especialmente vulnerable."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["network", "socket", "raw", "bytes", "network-input"],
    },
    {
        "id":                    "SRC-CON-016",
        "rule_type":             "source",
        "symbol":                "System.Net.Sockets.Socket.ReceiveAsync",
        "name":                  "Socket.ReceiveAsync() — datos de socket asíncrono",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   1.2,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "any",
        "description": (
            "Versión asíncrona de Socket.Receive — mismo nivel de riesgo. "
            "Los bytes recibidos en el buffer son tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["network", "socket", "async", "bytes", "network-input"],
    },

    # =========================================================================
    #  SECCIÓN 5: NAMED PIPES — IPC entre procesos
    # =========================================================================

    {
        "id":                    "SRC-CON-017",
        "rule_type":             "source",
        "symbol":                "System.IO.Pipes.NamedPipeServerStream",
        "name":                  "NamedPipeServerStream — datos de IPC via named pipe",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "NamedPipeServerStream recibe datos de otro proceso via named pipe. "
            "Severity_multiplier 0.9 — los pipes tienen restricciones de acceso "
            "del SO, pero el proceso cliente puede ser malicioso. "
            "En Windows, los pipes pueden ser accesibles via red (\\\\server\\pipe\\name)."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["ipc", "pipe", "stream", "network-input"],
    },
    {
        "id":                    "SRC-CON-018",
        "rule_type":             "source",
        "symbol":                "System.IO.Pipes.NamedPipeClientStream",
        "name":                  "NamedPipeClientStream — datos recibidos de un server pipe",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "NamedPipeClientStream conecta a un named pipe existente. "
            "Los datos que llegan del servidor son externos — tainted si "
            "el servidor puede ser comprometido o no es de confianza."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["ipc", "pipe", "client", "external-input"],
    },
    {
        "id":                    "SRC-CON-019",
        "rule_type":             "source",
        "symbol":                "System.IO.Pipes.AnonymousPipeServerStream",
        "name":                  "AnonymousPipeServerStream — pipe anónimo entre procesos",
        "taint_label":           "NETWORK_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "AnonymousPipeServerStream recibe datos de un proceso hijo via pipe anónimo. "
            "Si el proceso hijo puede ser controlado por un atacante → tainted."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["ipc", "pipe", "anonymous", "subprocess"],
    },

    # =========================================================================
    #  SECCIÓN 6: STREAMS DE ARCHIVO COMO FUENTE EXTERNA
    #  Cuando se leen archivos cuyo contenido puede ser controlado
    #  externamente (archivos subidos, archivos de configuración de usuario).
    # =========================================================================

    {
        "id":                    "SRC-CON-020",
        "rule_type":             "source",
        "symbol":                "System.IO.StreamReader.ReadToEnd",
        "name":                  "StreamReader.ReadToEnd() — contenido de stream externo",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "StreamReader.ReadToEnd() lee el contenido completo de un stream. "
            "Si el stream proviene de un archivo cargado por el usuario, "
            "una conexión de red, o un pipe externo → datos tainted. "
            "Severity_multiplier 0.85 — depende del origen del stream. "
            "El taint_analyzer debe rastrear si el StreamReader viene de "
            "una fuente externa (IFormFile, NetworkStream, PipeStream)."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["stream", "file", "external-input", "text"],
    },
    {
        "id":                    "SRC-CON-021",
        "rule_type":             "source",
        "symbol":                "System.IO.StreamReader.ReadLine",
        "name":                  "StreamReader.ReadLine() — línea de stream externo",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "StreamReader.ReadLine() lee una línea de un stream externo. "
            "Mismo análisis que ReadToEnd — el riesgo depende del origen del stream."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["stream", "file", "external-input", "line"],
    },
    {
        "id":                    "SRC-CON-022",
        "rule_type":             "source",
        "symbol":                "System.IO.StreamReader.ReadAsync",
        "name":                  "StreamReader.ReadAsync() — lectura asíncrona de stream externo",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Versión asíncrona de StreamReader.Read — mismo análisis de taint."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["stream", "async", "external-input"],
    },
    {
        "id":                    "SRC-CON-023",
        "rule_type":             "source",
        "symbol":                "System.IO.File.ReadAllText",
        "name":                  "File.ReadAllText() — contenido de archivo como fuente",
        "taint_label":           "STORED_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "File.ReadAllText() como SOURCE (no sink). "
            "Si el archivo contiene datos almacenados previamente que vinieron "
            "del usuario (archivos de upload, logs, exports), el contenido "
            "puede causar second-order injection. "
            "Severity_multiplier 0.7 — un paso más indirecto que input directo."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["file", "stored-input", "second-order", "read"],
    },

    # =========================================================================
    #  SECCIÓN 7: BASE DE DATOS — Second-order injection
    #  Resultados de DB como fuente de datos potencialmente tainted.
    # =========================================================================

    {
        "id":                    "SRC-CON-024",
        "rule_type":             "source",
        "symbol":                "System.Data.SqlClient.SqlDataReader.GetString",
        "name":                  "SqlDataReader.GetString() — dato de DB (second-order injection)",
        "taint_label":           "STORED_INPUT",
        "severity_multiplier":   0.65,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "SqlDataReader.GetString() lee un campo de texto de un resultado SQL. "
            "Si ese campo contiene datos almacenados que originalmente vinieron "
            "del usuario, puede causar second-order injection cuando se usa "
            "en otra query SQL, en un comando del sistema o en HTML. "
            "Severity_multiplier 0.65 — es un paso más indirecto pero real. "
            "Ejemplo clásico: "
            "  1. INSERT INTO users VALUES (@username)  ← se sanitiza "
            "  2. SELECT * FROM logs WHERE user='{username}' ← se construye dinámicamente "
            "     usando el valor recuperado de la BD → SQL Injection."
        ),
        "frameworks":            ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":                  ["database", "sql", "stored-input", "second-order", "sqldatareader"],
    },
    {
        "id":                    "SRC-CON-025",
        "rule_type":             "source",
        "symbol":                "System.Data.SqlClient.SqlDataReader.GetValue",
        "name":                  "SqlDataReader.GetValue() — valor de DB (second-order)",
        "taint_label":           "STORED_INPUT",
        "severity_multiplier":   0.65,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "SqlDataReader.GetValue() retorna el valor de un campo como object. "
            "Si el valor se convierte a string y se usa en código sensible → "
            "potencial second-order injection."
        ),
        "frameworks":            ["generic", "aspnetcore"],
        "tags":                  ["database", "stored-input", "second-order", "sqldatareader"],
    },
    {
        "id":                    "SRC-CON-026",
        "rule_type":             "source",
        "symbol":                "Microsoft.Data.SqlClient.SqlDataReader.GetString",
        "name":                  "Microsoft.Data SqlDataReader.GetString() — dato de DB (second-order)",
        "taint_label":           "STORED_INPUT",
        "severity_multiplier":   0.65,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Equivalente de SqlDataReader.GetString del driver moderno Microsoft.Data.SqlClient. "
            "Mismo riesgo de second-order injection."
        ),
        "frameworks":            ["generic", "aspnetcore"],
        "tags":                  ["database", "stored-input", "second-order", "microsoft.data"],
    },
    {
        "id":                    "SRC-CON-027",
        "rule_type":             "source",
        "symbol":                "System.Data.DataRow.Item",
        "name":                  "DataRow[] — dato de DataTable (second-order)",
        "taint_label":           "STORED_INPUT",
        "severity_multiplier":   0.65,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Acceso a un campo de DataRow (DataRow['campo'] o row.Field<string>('campo')). "
            "Si el DataTable se llenó con datos de una query SQL que incluye "
            "datos del usuario almacenados → second-order injection."
        ),
        "frameworks":            ["generic", "aspnetcore"],
        "tags":                  ["database", "datatable", "stored-input", "second-order"],
    },

    # =========================================================================
    #  SECCIÓN 8: SERVICIOS DE MENSAJERÍA — Message queues y buses
    #  Datos de mensajes que vienen de productores externos.
    # =========================================================================

    {
        "id":                    "SRC-CON-028",
        "rule_type":             "source",
        "symbol":                "System.Messaging.Message.Body",
        "name":                  "MSMQ Message.Body — cuerpo del mensaje de cola",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "System.Messaging (MSMQ) Message.Body contiene el cuerpo del mensaje "
            "que viene de otro sistema o proceso. "
            "Si el productor del mensaje puede ser controlado por un atacante "
            "(o si el bus no tiene autenticación fuerte) → tainted."
        ),
        "frameworks":            ["generic"],
        "tags":                  ["messaging", "msmq", "queue", "external-input"],
    },
    {
        "id":                    "SRC-CON-029",
        "rule_type":             "source",
        "symbol":                "RabbitMQ.Client.Events.BasicDeliverEventArgs",
        "name":                  "RabbitMQ BasicDeliverEventArgs.Body — mensaje de RabbitMQ",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "any",
        "description": (
            "Cuerpo del mensaje recibido desde RabbitMQ. "
            "Si la cola no tiene autenticación fuerte o el productor "
            "puede ser comprometido → datos tainted. "
            "Especialmente relevante si se deserializa directamente con BinaryFormatter."
        ),
        "frameworks":            ["generic", "aspnetcore"],
        "tags":                  ["messaging", "rabbitmq", "queue", "bytes", "external-input"],
    },
    {
        "id":                    "SRC-CON-030",
        "rule_type":             "source",
        "symbol":                "Azure.Messaging.ServiceBus.ServiceBusReceivedMessage",
        "name":                  "Azure Service Bus ReceivedMessage — mensaje de bus",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "authenticated",
        "description": (
            "Mensaje recibido de Azure Service Bus. "
            "Severity_multiplier 0.8 — requiere autenticación Azure, "
            "pero el contenido del mensaje puede venir de sistemas externos. "
            "Si Body se deserializa sin validación del tipo → Insecure Deserialization."
        ),
        "frameworks":            ["generic", "aspnetcore"],
        "tags":                  ["messaging", "azure", "servicebus", "external-input"],
    },
    {
        "id":                    "SRC-CON-031",
        "rule_type":             "source",
        "symbol":                "Confluent.Kafka.ConsumeResult",
        "name":                  "Kafka ConsumeResult — mensaje consumido de Kafka",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              False,
        "data_format":           "bytes",
        "authentication_context": "any",
        "description": (
            "Mensaje consumido de Apache Kafka. "
            "El valor (ConsumeResult.Message.Value) viene de un productor externo. "
            "Si se deserializa directamente o se usa en queries → tainted."
        ),
        "frameworks":            ["generic", "aspnetcore"],
        "tags":                  ["messaging", "kafka", "consumer", "external-input"],
    },

    # =========================================================================
    #  SECCIÓN 9: REGISTRO DE WINDOWS
    # =========================================================================

    {
        "id":                    "SRC-CON-032",
        "rule_type":             "source",
        "symbol":                "Microsoft.Win32.RegistryKey.GetValue",
        "name":                  "RegistryKey.GetValue() — valor del registro de Windows",
        "taint_label":           "ENVIRONMENT_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "RegistryKey.GetValue() lee un valor del registro de Windows. "
            "Severity_multiplier 0.7 — el registro requiere acceso al sistema, "
            "pero en sistemas comprometidos un atacante puede modificar valores "
            "del registro para inyectar datos maliciosos que luego se usan "
            "en el código de la aplicación."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["registry", "windows", "config", "environment-input"],
    },

    # =========================================================================
    #  SECCIÓN 10: SERVICIOS gRPC
    # =========================================================================

    {
        "id":                    "SRC-CON-033",
        "rule_type":             "source",
        "symbol":                "Grpc.Core.ServerCallContext",
        "name":                  "gRPC ServerCallContext — contexto de llamada gRPC",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.9,
        "implicit":              True,
        "data_format":           "object",
        "authentication_context": "any",
        "description": (
            "ServerCallContext contiene el contexto de una llamada gRPC entrante: "
            "metadata de request (headers), peer address, etc. "
            "Los parámetros del método gRPC (protobuf messages) son automáticamente "
            "detectados por el taint_analyzer. "
            "Este catálogo cubre el acceso DIRECTO al contexto."
        ),
        "frameworks":            ["grpc", "aspnetcore"],
        "tags":                  ["grpc", "service", "context", "user-input"],
    },
    {
        "id":                    "SRC-CON-034",
        "rule_type":             "source",
        "symbol":                "Grpc.Core.Metadata",
        "name":                  "gRPC Metadata — headers de request gRPC",
        "taint_label":           "USER_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Grpc.Core.Metadata contiene los headers de la llamada gRPC. "
            "Controlados por el cliente — si se usan en código sensible → tainted."
        ),
        "frameworks":            ["grpc", "aspnetcore"],
        "tags":                  ["grpc", "metadata", "headers", "user-input"],
    },

    # =========================================================================
    #  SECCIÓN 11: FUENTES EXTERNAS VÍA HTTP (como cliente, no servidor)
    #  Cuando la aplicación lee datos de APIs externas y los usa sin validar.
    # =========================================================================

    {
        "id":                    "SRC-CON-035",
        "rule_type":             "source",
        "symbol":                "System.Net.Http.HttpResponseMessage.Content",
        "name":                  "HttpResponseMessage.Content — respuesta HTTP de servicio externo",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "El contenido de una respuesta HTTP de un servicio externo. "
            "Severity_multiplier 0.8 — aunque el servicio externo sea de confianza, "
            "si el servicio es comprometido o devuelve datos inesperados "
            "y la aplicación los usa directamente en queries → tainted. "
            "Especialmente relevante en arquitecturas microservicio donde "
            "un servicio interno comprometido puede inyectar datos en otro."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["http", "client", "external", "response", "external-input"],
    },
    {
        "id":                    "SRC-CON-036",
        "rule_type":             "source",
        "symbol":                "System.Net.WebClient.DownloadString",
        "name":                  "WebClient.DownloadString() — contenido descargado de URL",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.8,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "WebClient.DownloadString() descarga el contenido de una URL como string. "
            "Si el contenido se usa en queries, comandos o paths → tainted. "
            "Especialmente peligroso si la URL es configurable."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["http", "client", "download", "external-input"],
    },

    # =========================================================================
    #  SECCIÓN 12: CONFIGURACIÓN DE LA APLICACIÓN
    #  Cuando la configuración puede ser modificada por actores externos.
    # =========================================================================

    {
        "id":                    "SRC-CON-037",
        "rule_type":             "source",
        "symbol":                "Microsoft.Extensions.Configuration.IConfiguration",
        "name":                  "IConfiguration — configuración de la aplicación",
        "taint_label":           "ENVIRONMENT_INPUT",
        "severity_multiplier":   0.6,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "IConfiguration de .NET lee configuración de múltiples fuentes: "
            "appsettings.json, variables de entorno, secretos, Azure Key Vault. "
            "Severity_multiplier 0.6 — la configuración generalmente es confiable, "
            "pero si se lee de variables de entorno controlables externamente "
            "o de Key Vault con acceso comprometido → puede ser tainted. "
            "Reportado con confianza low — requiere contexto adicional."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["config", "configuration", "environment-input", "appsettings"],
    },
    {
        "id":                    "SRC-CON-038",
        "rule_type":             "source",
        "symbol":                "System.Configuration.ConfigurationManager.AppSettings",
        "name":                  "ConfigurationManager.AppSettings — app.config / web.config",
        "taint_label":           "ENVIRONMENT_INPUT",
        "severity_multiplier":   0.55,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "ConfigurationManager.AppSettings lee valores de app.config o web.config. "
            "Severity_multiplier 0.55 — generalmente confiable, pero si el archivo "
            "de configuración puede ser modificado por un proceso externo → tainted. "
            "En algunos escenarios de escalada de privilegios en Windows, "
            "modificar app.config puede inyectar valores en la aplicación."
        ),
        "frameworks":            ["console", "aspnet_mvc", "generic"],
        "tags":                  ["config", "appsettings", "webconfig", "environment-input"],
    },

    # =========================================================================
    #  SECCIÓN 13: DNS Y RESOLUCIÓN DE NOMBRES
    # =========================================================================

    {
        "id":                    "SRC-CON-039",
        "rule_type":             "source",
        "symbol":                "System.Net.Dns.GetHostEntry",
        "name":                  "Dns.GetHostEntry() — resultado de resolución DNS",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "string",
        "authentication_context": "any",
        "description": (
            "Dns.GetHostEntry() resuelve un hostname a una dirección IP. "
            "El resultado puede ser manipulado con DNS rebinding o DNS spoofing. "
            "Si el hostname o la IP resultante se usa en código de seguridad "
            "(autorización basada en IP, SSRF checks) → puede ser bypasseado."
        ),
        "frameworks":            ["console", "generic", "aspnetcore"],
        "tags":                  ["dns", "network", "resolution", "external-input", "dns-rebinding"],
    },

    # =========================================================================
    #  SECCIÓN 14: PROCESOS EXTERNOS — Output de subprocesos
    # =========================================================================

    {
        "id":                    "SRC-CON-040",
        "rule_type":             "source",
        "symbol":                "System.Diagnostics.Process.StandardOutput",
        "name":                  "Process.StandardOutput — salida de subproceso",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.85,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "La salida estándar de un proceso hijo. "
            "Si el proceso hijo puede ser controlado por un atacante "
            "(o si su output puede ser manipulado), los datos son tainted. "
            "Especialmente relevante si se ejecutan comandos externos y "
            "su output se usa en queries o comandos posteriores → Command Injection."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["process", "subprocess", "stdout", "external-input"],
    },
    {
        "id":                    "SRC-CON-041",
        "rule_type":             "source",
        "symbol":                "System.Diagnostics.Process.StandardError",
        "name":                  "Process.StandardError — salida de error de subproceso",
        "taint_label":           "EXTERNAL_INPUT",
        "severity_multiplier":   0.7,
        "implicit":              False,
        "data_format":           "stream",
        "authentication_context": "any",
        "description": (
            "La salida de error estándar de un proceso hijo. "
            "Severity_multiplier 0.7 — menos comúnmente usada en código productivo, "
            "pero si se registra en logs o se muestra en UI sin encoding → Log Injection o XSS."
        ),
        "frameworks":            ["console", "generic"],
        "tags":                  ["process", "subprocess", "stderr", "external-input", "log-injection"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCIONES DE ACCESO AL CATÁLOGO
# ─────────────────────────────────────────────────────────────────────────────

def get_console_source_rules() -> list[dict]:
    """Retorna el catálogo completo de sources de consola y fuentes generales."""
    return CONSOLE_AND_GENERAL_SOURCES


def get_console_source_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in CONSOLE_AND_GENERAL_SOURCES}


def get_direct_user_input_sources() -> list[dict]:
    """
    Retorna fuentes de input directo del usuario (consola, CLI, args).
    Las más críticas — no requieren comprometer un sistema intermedio.
    """
    return [
        r for r in CONSOLE_AND_GENERAL_SOURCES
        if r.get("taint_label") == "USER_INPUT"
    ]


def get_network_sources() -> list[dict]:
    """Retorna sources de datos de red (TCP, UDP, sockets, pipes)."""
    return [
        r for r in CONSOLE_AND_GENERAL_SOURCES
        if r.get("taint_label") == "NETWORK_INPUT"
        or "network" in r.get("tags", [])
    ]


def get_second_order_sources() -> list[dict]:
    """
    Retorna sources de second-order injection (datos almacenados en BD).
    Se usan para detectar el patrón: almacenar → recuperar → usar sin re-sanitizar.
    """
    return [
        r for r in CONSOLE_AND_GENERAL_SOURCES
        if r.get("taint_label") == "STORED_INPUT"
        or "second-order" in r.get("tags", [])
    ]


def get_messaging_sources() -> list[dict]:
    """Retorna sources de sistemas de mensajería (MSMQ, RabbitMQ, Kafka, Azure SB)."""
    return [
        r for r in CONSOLE_AND_GENERAL_SOURCES
        if "messaging" in r.get("tags", [])
        or "queue" in r.get("tags", [])
    ]


def get_environment_sources() -> list[dict]:
    """Retorna sources de variables de entorno y configuración."""
    return [
        r for r in CONSOLE_AND_GENERAL_SOURCES
        if r.get("taint_label") == "ENVIRONMENT_INPUT"
    ]


def get_high_severity_sources() -> list[dict]:
    """
    Retorna sources con severity_multiplier >= 1.0.
    Son las más críticas para el taint analysis.
    """
    return [
        r for r in CONSOLE_AND_GENERAL_SOURCES
        if r.get("severity_multiplier", 1.0) >= 1.0
    ]


def get_source_taint_labels() -> dict[str, str]:
    """
    Retorna mapa {symbol_prefix: taint_label} para lookup rápido
    por el TaintAnalyzer.
    """
    return {
        rule["symbol"]: rule["taint_label"]
        for rule in CONSOLE_AND_GENERAL_SOURCES
    }


def get_source_severity_multipliers() -> dict[str, float]:
    """
    Retorna mapa {symbol_prefix: severity_multiplier} para ajuste de
    severidad en el VulnerabilityClassifier.
    """
    return {
        rule["symbol"]: rule.get("severity_multiplier", 1.0)
        for rule in CONSOLE_AND_GENERAL_SOURCES
    }


def get_all_taint_labels_unified() -> dict[str, str]:
    """
    Retorna mapa unificado {symbol: taint_label} de todos los taint labels
    de este módulo. Equivalente a get_source_taint_labels() pero con nombre
    más descriptivo para usar desde rule_loader.py.
    """
    return get_source_taint_labels()