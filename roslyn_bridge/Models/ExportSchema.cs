// =============================================================================
//  csharp-sast / roslyn_bridge / Models / ExportSchema.cs
// =============================================================================
//
//  CONTRATO DE DATOS ENTRE ROSLYN BRIDGE (C#) Y ENGINE PYTHON
//  ─────────────────────────────────────────────────────────────
//  Este archivo define el schema JSON canónico que el bridge exporta
//  y que el engine Python (ast_importer.py) consume.
//
//  REGLAS DE DISEÑO:
//    1. Todos los tipos son records (inmutables, value-equality).
//    2. Propiedades con JsonPropertyName en snake_case para Python.
//    3. Nullables explícitos — Python distingue null de ausente.
//    4. Sin lógica de negocio — solo DTOs puros.
//    5. IDs de nodo son GUIDs generados en SemanticExtractor,
//       estables dentro de un análisis (permiten referenciar
//       nodos desde el CFG/DFG).
//
//  JERARQUÍA DEL SCHEMA:
//    RoslynExportRoot
//      └── ExportMetadata            (info del análisis)
//      └── CompilationUnit           (usings, namespace, clases)
//            └── ClassExport[]
//                  └── MethodExport[]
//      └── SemanticNode[]            (todos los nodos de interés SAST)
//            └── ArgumentExport[]
//      └── ControlFlowExport         (CFG por método)
//            └── MethodCfgExport[]
//                  └── CfgBlockExport[]
//                  └── CfgEdgeExport[]
//      └── DataFlowExport            (asignaciones y flujos)
//            └── AssignmentExport[]
//            └── ParameterFlowExport[]
//      └── SymbolsExport             (external calls, atributos)
//            └── ExternalCallExport[]
//            └── AttributeAnnotation[]
//
// =============================================================================

using System.Text.Json.Serialization;

namespace RoslynBridge.Models;

// ─────────────────────────────────────────────────────────────────────────────
//  RAÍZ DEL EXPORT
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Objeto raíz del JSON que el bridge envía al engine Python.
/// El engine Python lo deserializa en ast_importer.py.
/// </summary>
public sealed record RoslynExportRoot(
    [property: JsonPropertyName("metadata")]
    ExportMetadata Metadata,

    [property: JsonPropertyName("compilation_unit")]
    CompilationUnit CompilationUnit,

    [property: JsonPropertyName("semantic_nodes")]
    IReadOnlyList<SemanticNode> SemanticNodes,

    [property: JsonPropertyName("control_flow")]
    ControlFlowExport ControlFlow,

    [property: JsonPropertyName("data_flow")]
    DataFlowExport DataFlow,

    [property: JsonPropertyName("symbols")]
    SymbolsExport Symbols
);

// ─────────────────────────────────────────────────────────────────────────────
//  METADATA DEL ANÁLISIS
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Información contextual del análisis.
/// El engine Python la usa para seleccionar reglas de framework.
/// </summary>
public sealed record ExportMetadata(
    /// <summary>Lista de archivos analizados (rutas absolutas).</summary>
    [property: JsonPropertyName("files")]
    IReadOnlyList<string> Files,

    /// <summary>Versión de C# detectada: "CSharp12", "CSharp11", etc.</summary>
    [property: JsonPropertyName("language_version")]
    string LanguageVersion,

    /// <summary>
    /// Framework principal detectado: "aspnetcore", "aspnet_mvc",
    /// "wcf", "winforms", "ef_core", "generic".
    /// Null si no se detectó framework específico.
    /// </summary>
    [property: JsonPropertyName("framework_detected")]
    string? FrameworkDetected,

    /// <summary>Paquetes NuGet referenciados detectados (para reglas de Dapper, etc.).</summary>
    [property: JsonPropertyName("nuget_references")]
    IReadOnlyList<string> NugetReferences,

    /// <summary>Errores de compilación no fatales (el análisis continúa).</summary>
    [property: JsonPropertyName("compilation_errors")]
    IReadOnlyList<CompilationErrorExport> CompilationErrors,

    /// <summary>Timestamp UTC ISO-8601 del análisis.</summary>
    [property: JsonPropertyName("analysis_timestamp")]
    string AnalysisTimestamp,

    /// <summary>Versión del Roslyn Bridge.</summary>
    [property: JsonPropertyName("bridge_version")]
    string BridgeVersion
);

/// <summary>Error de compilación no fatal (archivo con sintaxis incorrecta).</summary>
public sealed record CompilationErrorExport(
    [property: JsonPropertyName("file")]
    string File,

    [property: JsonPropertyName("line")]
    int Line,

    [property: JsonPropertyName("message")]
    string Message,

    [property: JsonPropertyName("severity")]
    string Severity  // "Error" | "Warning" | "Info"
);

// ─────────────────────────────────────────────────────────────────────────────
//  COMPILATION UNIT — ESTRUCTURA ESTÁTICA DEL CÓDIGO
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Estructura estática del código: namespaces, clases, métodos.
/// El engine Python la usa para construir el call graph y
/// el grafo de herencia.
/// </summary>
public sealed record CompilationUnit(
    /// <summary>Todas las directivas using del proyecto.</summary>
    [property: JsonPropertyName("usings")]
    IReadOnlyList<string> Usings,

    /// <summary>Namespace raíz del proyecto.</summary>
    [property: JsonPropertyName("root_namespace")]
    string? RootNamespace,

    /// <summary>Clases encontradas en el código analizado.</summary>
    [property: JsonPropertyName("classes")]
    IReadOnlyList<ClassExport> Classes
);

/// <summary>Representación de una clase o interfaz en el código analizado.</summary>
public sealed record ClassExport(
    [property: JsonPropertyName("class_id")]
    string ClassId,

    [property: JsonPropertyName("name")]
    string Name,

    /// <summary>Nombre completo incluyendo namespace: "MyApp.Controllers.UserController".</summary>
    [property: JsonPropertyName("full_name")]
    string FullName,

    [property: JsonPropertyName("kind")]
    string Kind,  // "class" | "interface" | "struct" | "record" | "enum"

    [property: JsonPropertyName("file")]
    string File,

    [property: JsonPropertyName("line")]
    int Line,

    /// <summary>Clase base resuelta a nombre completo: "Microsoft.AspNetCore.Mvc.ControllerBase".</summary>
    [property: JsonPropertyName("base_class")]
    string? BaseClass,

    [property: JsonPropertyName("interfaces")]
    IReadOnlyList<string> Interfaces,

    /// <summary>Atributos de la clase: [ApiController], [Route], etc.</summary>
    [property: JsonPropertyName("attributes")]
    IReadOnlyList<string> Attributes,

    [property: JsonPropertyName("is_abstract")]
    bool IsAbstract,

    [property: JsonPropertyName("is_partial")]
    bool IsPartial,

    [property: JsonPropertyName("methods")]
    IReadOnlyList<MethodExport> Methods,

    [property: JsonPropertyName("fields")]
    IReadOnlyList<FieldExport> Fields,

    [property: JsonPropertyName("properties")]
    IReadOnlyList<PropertyExport> Properties
);

/// <summary>Representación de un método dentro de una clase.</summary>
public sealed record MethodExport(
    [property: JsonPropertyName("method_id")]
    string MethodId,

    [property: JsonPropertyName("name")]
    string Name,

    /// <summary>Firma completa: "public async Task&lt;IActionResult&gt; GetUser(string id)".</summary>
    [property: JsonPropertyName("signature")]
    string Signature,

    /// <summary>Nombre de tipo de retorno resuelto: "System.Threading.Tasks.Task`1[Microsoft.AspNetCore.Mvc.IActionResult]".</summary>
    [property: JsonPropertyName("return_type")]
    string ReturnType,

    [property: JsonPropertyName("is_async")]
    bool IsAsync,

    [property: JsonPropertyName("is_static")]
    bool IsStatic,

    [property: JsonPropertyName("accessibility")]
    string Accessibility,  // "public" | "private" | "protected" | "internal"

    [property: JsonPropertyName("parameters")]
    IReadOnlyList<ParameterExport> Parameters,

    [property: JsonPropertyName("attributes")]
    IReadOnlyList<string> Attributes,

    [property: JsonPropertyName("file")]
    string File,

    [property: JsonPropertyName("line_start")]
    int LineStart,

    [property: JsonPropertyName("line_end")]
    int LineEnd,

    /// <summary>
    /// true si el método es un endpoint HTTP (tiene [HttpGet], [HttpPost], etc.)
    /// o es un action method de WCF [OperationContract].
    /// Permite al engine Python priorizar el análisis de endpoints.
    /// </summary>
    [property: JsonPropertyName("is_entry_point")]
    bool IsEntryPoint,

    [property: JsonPropertyName("containing_class_id")]
    string ContainingClassId
);

/// <summary>Parámetro de un método.</summary>
public sealed record ParameterExport(
    [property: JsonPropertyName("name")]
    string Name,

    /// <summary>Tipo resuelto: "System.String", "System.Int32", etc.</summary>
    [property: JsonPropertyName("resolved_type")]
    string ResolvedType,

    [property: JsonPropertyName("position")]
    int Position,

    [property: JsonPropertyName("has_default")]
    bool HasDefault,

    /// <summary>Atributos de binding: [FromQuery], [FromBody], [FromRoute], etc.</summary>
    [property: JsonPropertyName("binding_attributes")]
    IReadOnlyList<string> BindingAttributes
);

/// <summary>Campo de una clase.</summary>
public sealed record FieldExport(
    [property: JsonPropertyName("name")]
    string Name,

    [property: JsonPropertyName("resolved_type")]
    string ResolvedType,

    [property: JsonPropertyName("is_readonly")]
    bool IsReadonly,

    [property: JsonPropertyName("is_static")]
    bool IsStatic,

    [property: JsonPropertyName("accessibility")]
    string Accessibility
);

/// <summary>Propiedad de una clase.</summary>
public sealed record PropertyExport(
    [property: JsonPropertyName("name")]
    string Name,

    [property: JsonPropertyName("resolved_type")]
    string ResolvedType,

    [property: JsonPropertyName("has_getter")]
    bool HasGetter,

    [property: JsonPropertyName("has_setter")]
    bool HasSetter,

    [property: JsonPropertyName("accessibility")]
    string Accessibility,

    [property: JsonPropertyName("attributes")]
    IReadOnlyList<string> Attributes
);

// ─────────────────────────────────────────────────────────────────────────────
//  SEMANTIC NODES — EL CORAZÓN DEL ANÁLISIS SAST
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Nodo semántico de interés para el análisis SAST.
/// Representa invocaciones de métodos, creación de objetos,
/// asignaciones, accesos a propiedades y expresiones relevantes.
///
/// La diferencia entre un SAST amateur y uno enterprise está aquí:
/// resolved_symbol da el nombre completo del símbolo resuelto por
/// el compilador, no un texto extraído con regex.
///
/// Ejemplo:
///   Texto:           "SqlCommand(userInput)"
///   resolved_symbol: "System.Data.SqlClient.SqlCommand..ctor(System.String)"
///
/// El engine Python hace match contra resolved_symbol en el catálogo
/// de sinks, eliminando falsos positivos por alias, herencia o shadowing.
/// </summary>
public sealed record SemanticNode(
    /// <summary>ID único del nodo dentro del análisis (GUID).</summary>
    [property: JsonPropertyName("node_id")]
    string NodeId,

    /// <summary>
    /// Tipo de nodo Roslyn:
    ///   "InvocationExpression"     → llamada a método
    ///   "ObjectCreationExpression" → new T(...)
    ///   "MemberAccessExpression"   → obj.Property
    ///   "AssignmentExpression"     → x = ...
    ///   "ReturnStatement"          → return ...
    ///   "AwaitExpression"          → await ...
    ///   "ThrowStatement"           → throw ...
    ///   "LocalDeclaration"         → var x = ...
    /// </summary>
    [property: JsonPropertyName("kind")]
    string Kind,

    /// <summary>Texto del nodo tal como aparece en el código fuente.</summary>
    [property: JsonPropertyName("text")]
    string Text,

    [property: JsonPropertyName("file")]
    string File,

    [property: JsonPropertyName("line")]
    int Line,

    [property: JsonPropertyName("column")]
    int Column,

    /// <summary>
    /// Símbolo resuelto por Roslyn. Para invocaciones de método es
    /// el nombre de metadata completo:
    ///   "System.Data.SqlClient.SqlCommand..ctor"
    ///   "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw"
    ///
    /// Null si el símbolo no pudo resolverse (código incompleto).
    /// </summary>
    [property: JsonPropertyName("resolved_symbol")]
    string? ResolvedSymbol,

    /// <summary>Tipo de retorno o tipo del nodo resuelto por Roslyn.</summary>
    [property: JsonPropertyName("resolved_type")]
    string? ResolvedType,

    /// <summary>ID del método contenedor (referencia a MethodExport.MethodId).</summary>
    [property: JsonPropertyName("containing_method_id")]
    string? ContainingMethodId,

    /// <summary>ID de la clase contenedora (referencia a ClassExport.ClassId).</summary>
    [property: JsonPropertyName("containing_class_id")]
    string? ContainingClassId,

    /// <summary>
    /// Argumentos de la invocación con información de data flow.
    /// El taint_analyzer.py recorre estos argumentos buscando
    /// datos que provienen de sources (HttpRequest, etc.).
    /// </summary>
    [property: JsonPropertyName("arguments")]
    IReadOnlyList<ArgumentExport> Arguments,

    /// <summary>
    /// true si este nodo es una llamada asíncrona (await, Task, ValueTask).
    /// El DFG builder necesita saberlo para propagar taint correctamente
    /// a través de continuaciones async.
    /// </summary>
    [property: JsonPropertyName("is_async_call")]
    bool IsAsyncCall,

    /// <summary>
    /// true si el nodo está dentro de un bloque try/catch.
    /// Las excepciones capturadas pueden sanitizar ciertos flujos.
    /// </summary>
    [property: JsonPropertyName("is_in_try_block")]
    bool IsInTryBlock,

    /// <summary>
    /// Nodos padre (hasta 3 niveles) para contexto de análisis.
    /// Permite al engine Python entender si una llamada está dentro
    /// de una condición, un loop, un using, etc.
    /// </summary>
    [property: JsonPropertyName("parent_context")]
    IReadOnlyList<string> ParentContext
);

/// <summary>
/// Argumento de una invocación de método con información de data flow.
/// Esta es la pieza que permite al taint_analyzer rastrear si el dato
/// viene de un parámetro del método (posible source) o es un literal
/// (seguro por definición).
/// </summary>
public sealed record ArgumentExport(
    [property: JsonPropertyName("position")]
    int Position,

    /// <summary>Texto del argumento en el código fuente.</summary>
    [property: JsonPropertyName("text")]
    string Text,

    /// <summary>Tipo resuelto: "System.String", "System.Int32", etc.</summary>
    [property: JsonPropertyName("resolved_type")]
    string? ResolvedType,

    /// <summary>
    /// true si el argumento es un literal constante ("SELECT *", 42, true).
    /// Los literales son seguros — no pueden contener input del atacante.
    /// </summary>
    [property: JsonPropertyName("is_literal")]
    bool IsLiteral,

    /// <summary>
    /// Origen del dato:
    ///   "parameter"         → viene de un parámetro del método contenedor
    ///   "field"             → viene de un campo de la clase
    ///   "local_variable"    → viene de una variable local
    ///   "return_value"      → resultado de otra invocación
    ///   "literal"           → valor constante en el código
    ///   "unknown"           → no pudo determinarse
    /// </summary>
    [property: JsonPropertyName("data_flow_origin")]
    string DataFlowOrigin,

    /// <summary>
    /// Si data_flow_origin es "parameter", nombre del parámetro origen.
    /// El engine Python buscará si ese parámetro viene de una source
    /// (HttpRequest.QueryString, etc.).
    /// </summary>
    [property: JsonPropertyName("origin_parameter_name")]
    string? OriginParameterName,

    /// <summary>
    /// Si data_flow_origin es "return_value", node_id de la invocación
    /// que produce el valor. Permite al DFG builder encadenar flujos.
    /// </summary>
    [property: JsonPropertyName("origin_node_id")]
    string? OriginNodeId,

    /// <summary>
    /// Nombre del parámetro nombrado si se usa sintaxis: método(name: value).
    /// Null para argumentos posicionales.
    /// </summary>
    [property: JsonPropertyName("named_parameter")]
    string? NamedParameter
);

// ─────────────────────────────────────────────────────────────────────────────
//  CONTROL FLOW GRAPH (CFG)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// CFG completo del proyecto, organizado por método.
/// Roslyn genera el CFG nativo del compilador (más preciso que
/// cualquier CFG construido manualmente desde el AST).
/// </summary>
public sealed record ControlFlowExport(
    [property: JsonPropertyName("methods")]
    IReadOnlyList<MethodCfgExport> Methods
);

/// <summary>CFG de un método individual.</summary>
public sealed record MethodCfgExport(
    [property: JsonPropertyName("method_id")]
    string MethodId,

    [property: JsonPropertyName("method_name")]
    string MethodName,

    [property: JsonPropertyName("cfg_blocks")]
    IReadOnlyList<CfgBlockExport> Blocks,

    [property: JsonPropertyName("cfg_edges")]
    IReadOnlyList<CfgEdgeExport> Edges,

    /// <summary>ID del bloque de entrada del CFG.</summary>
    [property: JsonPropertyName("entry_block_id")]
    string EntryBlockId,

    /// <summary>IDs de los bloques de salida (return, throw).</summary>
    [property: JsonPropertyName("exit_block_ids")]
    IReadOnlyList<string> ExitBlockIds
);

/// <summary>
/// Bloque básico del CFG.
/// Un bloque básico es una secuencia de instrucciones sin branches internas.
/// Todas las instrucciones de un bloque se ejecutan si se ejecuta la primera.
/// </summary>
public sealed record CfgBlockExport(
    [property: JsonPropertyName("block_id")]
    string BlockId,

    /// <summary>Tipo de bloque: "entry", "exit", "basic", "try", "catch", "finally".</summary>
    [property: JsonPropertyName("kind")]
    string Kind,

    /// <summary>IDs de los SemanticNodes que ocurren en este bloque.</summary>
    [property: JsonPropertyName("node_ids")]
    IReadOnlyList<string> NodeIds,

    [property: JsonPropertyName("line_start")]
    int LineStart,

    [property: JsonPropertyName("line_end")]
    int LineEnd,

    /// <summary>
    /// Condición de la rama (para bloques de decisión).
    /// Texto de la expresión booleana evaluada en este bloque.
    /// </summary>
    [property: JsonPropertyName("branch_condition")]
    string? BranchCondition,

    [property: JsonPropertyName("is_exception_handler")]
    bool IsExceptionHandler
);

/// <summary>
/// Arista del CFG representando transferencia de control entre bloques.
/// </summary>
public sealed record CfgEdgeExport(
    [property: JsonPropertyName("from_block_id")]
    string FromBlockId,

    [property: JsonPropertyName("to_block_id")]
    string ToBlockId,

    /// <summary>
    /// Tipo de arista:
    ///   "sequential"   → flujo normal entre bloques consecutivos
    ///   "true_branch"  → rama true de un if/while/for
    ///   "false_branch" → rama false
    ///   "exception"    → flujo de excepción hacia catch/finally
    ///   "return"       → retorno desde el método
    ///   "throw"        → lanzamiento de excepción
    /// </summary>
    [property: JsonPropertyName("edge_kind")]
    string EdgeKind
);

// ─────────────────────────────────────────────────────────────────────────────
//  DATA FLOW EXPORT
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Información de flujo de datos: asignaciones, flujos de parámetros,
/// valores de retorno. El DFG builder de Python usa esto para construir
/// el grafo de dependencias de datos.
/// </summary>
public sealed record DataFlowExport(
    /// <summary>Asignaciones de variables locales y campos.</summary>
    [property: JsonPropertyName("assignments")]
    IReadOnlyList<AssignmentExport> Assignments,

    /// <summary>Flujos de datos desde parámetros de entrada hacia expresiones.</summary>
    [property: JsonPropertyName("parameter_flows")]
    IReadOnlyList<ParameterFlowExport> ParameterFlows,

    /// <summary>Valores de retorno de métodos (para inter-procedural analysis).</summary>
    [property: JsonPropertyName("return_flows")]
    IReadOnlyList<ReturnFlowExport> ReturnFlows
);

/// <summary>
/// Asignación de valor a una variable o campo.
/// x = GetInput() → el taint de GetInput() se propaga a x.
/// </summary>
public sealed record AssignmentExport(
    [property: JsonPropertyName("assignment_id")]
    string AssignmentId,

    /// <summary>Nombre de la variable/campo que recibe el valor.</summary>
    [property: JsonPropertyName("target_name")]
    string TargetName,

    [property: JsonPropertyName("target_type")]
    string? TargetType,

    /// <summary>ID del SemanticNode que produce el valor asignado.</summary>
    [property: JsonPropertyName("source_node_id")]
    string? SourceNodeId,

    /// <summary>Texto del valor asignado (para context en reportes).</summary>
    [property: JsonPropertyName("source_text")]
    string SourceText,

    [property: JsonPropertyName("is_literal")]
    bool IsLiteral,

    [property: JsonPropertyName("containing_method_id")]
    string ContainingMethodId,

    [property: JsonPropertyName("line")]
    int Line
);

/// <summary>
/// Flujo de un parámetro hacia variables locales o calls dentro del método.
/// Permite al taint analyzer rastrear cómo el input del atacante
/// (que llega como parámetro) se propaga por el cuerpo del método.
/// </summary>
public sealed record ParameterFlowExport(
    [property: JsonPropertyName("method_id")]
    string MethodId,

    [property: JsonPropertyName("parameter_name")]
    string ParameterName,

    [property: JsonPropertyName("parameter_type")]
    string ParameterType,

    /// <summary>
    /// IDs de los SemanticNodes donde este parámetro es usado como argumento.
    /// El taint analyzer recorre estos para detectar si llegan a un sink.
    /// </summary>
    [property: JsonPropertyName("used_in_node_ids")]
    IReadOnlyList<string> UsedInNodeIds,

    /// <summary>
    /// IDs de los AssignmentExports donde este parámetro se asigna a otra variable.
    /// Permite rastrear alias: var query = id; → SqlCommand(query)
    /// </summary>
    [property: JsonPropertyName("assigned_to_ids")]
    IReadOnlyList<string> AssignedToIds
);

/// <summary>
/// Valor de retorno de un método.
/// Permite al DFG builder propagar taint inter-proceduralmente:
/// si GetUserName() retorna datos tainted, llamadas a GetUserName()
/// también están tainted.
/// </summary>
public sealed record ReturnFlowExport(
    [property: JsonPropertyName("method_id")]
    string MethodId,

    /// <summary>IDs de los SemanticNodes retornados (puede ser >1 con múltiples returns).</summary>
    [property: JsonPropertyName("returned_node_ids")]
    IReadOnlyList<string> ReturnedNodeIds,

    [property: JsonPropertyName("return_type")]
    string ReturnType,

    /// <summary>true si alguna rama retorna un valor tainted (parámetro o externa).</summary>
    [property: JsonPropertyName("may_return_tainted")]
    bool MayReturnTainted
);

// ─────────────────────────────────────────────────────────────────────────────
//  SYMBOLS EXPORT — LLAMADAS EXTERNAS Y ATRIBUTOS
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Información de símbolos externos y anotaciones de atributos.
/// El framework_analyzer.py usa los atributos para aplicar
/// reglas específicas de ASP.NET Core, WCF, etc.
/// </summary>
public sealed record SymbolsExport(
    /// <summary>Llamadas a métodos de librerías externas (NuGet, BCL).</summary>
    [property: JsonPropertyName("external_calls")]
    IReadOnlyList<ExternalCallExport> ExternalCalls,

    /// <summary>Atributos relevantes para el análisis SAST.</summary>
    [property: JsonPropertyName("attribute_annotations")]
    IReadOnlyList<AttributeAnnotation> AttributeAnnotations
);

/// <summary>Llamada a un método externo (biblioteca NuGet o BCL).</summary>
public sealed record ExternalCallExport(
    [property: JsonPropertyName("node_id")]
    string NodeId,

    /// <summary>Nombre completo del símbolo externo resuelto por Roslyn.</summary>
    [property: JsonPropertyName("resolved_symbol")]
    string ResolvedSymbol,

    /// <summary>Assembly donde está definido el símbolo.</summary>
    [property: JsonPropertyName("assembly")]
    string Assembly,

    [property: JsonPropertyName("line")]
    int Line,

    [property: JsonPropertyName("file")]
    string File
);

/// <summary>
/// Anotación de atributo relevante para el análisis SAST.
/// Ejemplos:
///   [HttpGet("/users/{id}")]   → endpoint de entrada de datos
///   [ValidateAntiForgeryToken] → sanitizador de CSRF
///   [Authorize]                → restricción de acceso
///   [AllowAnonymous]           → potencial superficie de ataque
/// </summary>
public sealed record AttributeAnnotation(
    /// <summary>ID del método o clase anotado.</summary>
    [property: JsonPropertyName("target_id")]
    string TargetId,

    /// <summary>Tipo del target: "method" | "class" | "parameter" | "property".</summary>
    [property: JsonPropertyName("target_kind")]
    string TargetKind,

    /// <summary>Nombre del atributo: "HttpGet", "ValidateAntiForgeryToken", etc.</summary>
    [property: JsonPropertyName("attribute_name")]
    string AttributeName,

    /// <summary>Nombre completo del atributo resuelto: "Microsoft.AspNetCore.Mvc.HttpGetAttribute".</summary>
    [property: JsonPropertyName("resolved_attribute")]
    string? ResolvedAttribute,

    /// <summary>Argumentos del atributo: [HttpGet("/route")] → ["/route"].</summary>
    [property: JsonPropertyName("arguments")]
    IReadOnlyList<string> Arguments
);

// ─────────────────────────────────────────────────────────────────────────────
//  REQUEST / RESPONSE MODELS (para la Minimal API)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Request recibido por POST /analyze.
/// El engine Python (roslyn_client.py) construye este objeto.
/// </summary>
public sealed record AnalysisRequest(
    /// <summary>Lista de archivos .cs a analizar (rutas absolutas).</summary>
    [property: JsonPropertyName("files")]
    IReadOnlyList<string> Files,

    /// <summary>
    /// Rutas adicionales de ensamblados de referencia.
    /// Permite a Roslyn resolver símbolos de frameworks instalados.
    /// Si es null, se usan los ensamblados del BCL de .NET 8.
    /// </summary>
    [property: JsonPropertyName("reference_assemblies")]
    IReadOnlyList<string>? ReferenceAssemblies,

    /// <summary>
    /// Versión de C# a usar para el parser.
    /// Null → Roslyn auto-detecta desde el código.
    /// </summary>
    [property: JsonPropertyName("language_version")]
    string? LanguageVersion,

    /// <summary>
    /// Si true, incluye nodos de tipo literal y nodos sin símbolo resuelto.
    /// Útil durante desarrollo del engine. Default: false (más eficiente).
    /// </summary>
    [property: JsonPropertyName("include_unresolved")]
    bool IncludeUnresolved
);

/// <summary>
/// Response del endpoint GET /health.
/// El scanner.py la usa para verificar disponibilidad del bridge
/// antes de iniciar el análisis.
/// </summary>
public sealed record HealthResponse(
    [property: JsonPropertyName("status")]
    string Status,  // "healthy" | "degraded" | "unhealthy"

    [property: JsonPropertyName("version")]
    string Version,

    [property: JsonPropertyName("dotnet_version")]
    string DotnetVersion,

    [property: JsonPropertyName("roslyn_version")]
    string RoslynVersion,

    [property: JsonPropertyName("timestamp")]
    string Timestamp
);

