// =============================================================================
//  csharp-sast / roslyn_bridge / Models / SemanticNode.cs
// =============================================================================
//
//  MODELO INTERNO DE NODO SEMÁNTICO
//  ──────────────────────────────────
//  Complementa ExportSchema.cs con:
//    • Enums tipados para Kind, DataFlowOrigin, EdgeKind
//    • Extensiones de dominio SAST sobre los records del schema
//    • Constantes de clasificación de nodos
//    • Helpers de construcción usados por SemanticExtractor y DfgExtractor
//
//  SEPARACIÓN DE RESPONSABILIDADES:
//    ExportSchema.cs  → DTOs puros (lo que sale al JSON / engine Python)
//    SemanticNode.cs  → Enums, constantes y extensiones de dominio interno
//                       (lo que usa el bridge internamente antes de serializar)
//
//  Este archivo NO agrega propiedades al JSON exportado.
//  Solo enriquece el modelo interno del bridge C#.
//
// =============================================================================

using RoslynBridge.Models;

namespace RoslynBridge.Models;

// ─────────────────────────────────────────────────────────────────────────────
//  ENUMS DE DOMINIO
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Tipos de nodo semántico que el bridge puede exportar.
/// Corresponde 1:1 con el campo SemanticNode.Kind del ExportSchema.
/// Usar este enum internamente evita strings mágicos dispersos en el código.
/// </summary>
public enum SemanticNodeKind
{
    /// <summary>Llamada a método: foo.Bar(args).</summary>
    InvocationExpression,

    /// <summary>Creación de objeto: new SqlCommand(query).</summary>
    ObjectCreationExpression,

    /// <summary>Acceso a miembro: obj.Property.</summary>
    MemberAccessExpression,

    /// <summary>Asignación: x = GetInput().</summary>
    AssignmentExpression,

    /// <summary>Retorno de valor: return query.</summary>
    ReturnStatement,

    /// <summary>Expresión await: await service.GetAsync().</summary>
    AwaitExpression,

    /// <summary>Declaración de variable local: var query = id.</summary>
    LocalDeclaration,

    /// <summary>Lanzamiento de excepción: throw new Exception(msg).</summary>
    ThrowStatement,

    /// <summary>Expresión de interpolación de string: $"SELECT * WHERE id={id}".</summary>
    InterpolatedStringExpression,

    /// <summary>Inicializador de array o colección.</summary>
    CollectionInitializer,
}

/// <summary>
/// Origen del flujo de datos de un argumento en una invocación.
/// El taint_analyzer.py usa este campo para determinar si un argumento
/// puede contener input del atacante sin recorrer el grafo completo.
/// </summary>
public enum DataFlowOriginKind
{
    /// <summary>
    /// Viene de un parámetro del método contenedor.
    /// POTENCIALMENTE TAINTED si el método es entry point (HttpGet, etc.).
    /// </summary>
    Parameter,

    /// <summary>
    /// Viene de un campo de la clase (inyectado por DI, leído de config).
    /// Requiere análisis adicional para determinar si es tainted.
    /// </summary>
    Field,

    /// <summary>
    /// Viene de una variable local (alias de parámetro u otra expresión).
    /// El DFG builder rastrea el origen real.
    /// </summary>
    LocalVariable,

    /// <summary>
    /// Viene del valor de retorno de otra invocación.
    /// El DFG builder encadena el análisis hacia esa invocación.
    /// </summary>
    ReturnValue,

    /// <summary>
    /// Valor literal constante en el código fuente.
    /// SEGURO: los literales no pueden contener input del atacante.
    /// </summary>
    Literal,

    /// <summary>No se pudo determinar el origen.</summary>
    Unknown,
}

/// <summary>
/// Tipo de arista en el CFG.
/// Corresponde 1:1 con CfgEdgeExport.EdgeKind.
/// </summary>
public enum CfgEdgeKind
{
    /// <summary>Flujo secuencial entre bloques consecutivos.</summary>
    Sequential,

    /// <summary>Rama verdadera de una condición (if true, while condition true).</summary>
    TrueBranch,

    /// <summary>Rama falsa de una condición.</summary>
    FalseBranch,

    /// <summary>Flujo de excepción hacia un bloque catch o finally.</summary>
    Exception,

    /// <summary>Retorno normal del método.</summary>
    Return,

    /// <summary>Lanzamiento de excepción sin captura.</summary>
    Throw,
}

/// <summary>
/// Tipo de bloque básico en el CFG.
/// Corresponde 1:1 con CfgBlockExport.Kind.
/// </summary>
public enum CfgBlockKind
{
    Entry,
    Exit,
    Basic,
    Try,
    Catch,
    Finally,
}

/// <summary>
/// Framework detectado en el proyecto analizado.
/// Determina qué conjunto de reglas de sources y sinks activa el engine Python.
/// </summary>
public enum DetectedFramework
{
    /// <summary>ASP.NET Core (MVC, Minimal APIs, Razor Pages).</summary>
    AspNetCore,

    /// <summary>ASP.NET MVC clásico (System.Web).</summary>
    AspNetMvc,

    /// <summary>Windows Communication Foundation.</summary>
    Wcf,

    /// <summary>Windows Forms.</summary>
    WinForms,

    /// <summary>Entity Framework Core.</summary>
    EfCore,

    /// <summary>Sin framework específico detectado.</summary>
    Generic,
}

// ─────────────────────────────────────────────────────────────────────────────
//  CONSTANTES DE CLASIFICACIÓN SAST
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Catálogo de símbolos resueltos que el bridge preclasifica como
/// POTENCIALMENTE relevantes para SAST durante la extracción.
///
/// IMPORTANTE: Esta preclasificación es una optimización del bridge,
/// NO la clasificación definitiva de vulnerabilidades (eso es del engine Python).
/// Su propósito es reducir el volumen de nodos exportados cuando
/// IncludeUnresolved = false.
///
/// El engine Python tiene su propio catálogo completo en:
///   core/rules/sinks/
///   core/rules/sources/
/// </summary>
public static class KnownSastSymbols
{
    // ── Sinks de SQL Injection ────────────────────────────────────────────────
    public static readonly HashSet<string> SqlSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Data.SqlClient.SqlCommand",
        "System.Data.SqlClient.SqlCommand..ctor",
        "Microsoft.Data.SqlClient.SqlCommand",
        "Microsoft.Data.SqlClient.SqlCommand..ctor",
        "System.Data.OleDb.OleDbCommand",
        "System.Data.Odbc.OdbcCommand",
        "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw",
        "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw",
        "Dapper.SqlMapper.Execute",
        "Dapper.SqlMapper.Query",
        "Dapper.SqlMapper.QueryAsync",
        "Dapper.SqlMapper.ExecuteAsync",
        "NPoco.Database.Execute",
    };

    // ── Sinks de Command Injection ────────────────────────────────────────────
    public static readonly HashSet<string> CommandSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Diagnostics.Process.Start",
        "System.Diagnostics.ProcessStartInfo..ctor",
        "System.Diagnostics.ProcessStartInfo.FileName",
        "System.Diagnostics.ProcessStartInfo.Arguments",
        "System.Runtime.InteropServices.Marshal.StringToHGlobalAnsi",
    };

    // ── Sinks de Path Traversal ───────────────────────────────────────────────
    public static readonly HashSet<string> PathSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.IO.File.ReadAllText",
        "System.IO.File.WriteAllText",
        "System.IO.File.Open",
        "System.IO.File.Delete",
        "System.IO.File.Exists",
        "System.IO.File.ReadAllBytes",
        "System.IO.File.WriteAllBytes",
        "System.IO.Directory.GetFiles",
        "System.IO.Path.Combine",
        "System.IO.FileStream..ctor",
        "System.IO.StreamReader..ctor",
        "System.IO.StreamWriter..ctor",
    };

    // ── Sinks de Deserialización Insegura ─────────────────────────────────────
    public static readonly HashSet<string> DeserializationSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",
        "System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize",
        "System.Web.Script.Serialization.JavaScriptSerializer.Deserialize",
        "System.Web.Script.Serialization.JavaScriptSerializer.DeserializeObject",
        "Newtonsoft.Json.JsonConvert.DeserializeObject",
        "System.Xml.Serialization.XmlSerializer.Deserialize",
        "System.Runtime.Serialization.DataContractSerializer.ReadObject",
        "System.Runtime.Serialization.Json.DataContractJsonSerializer.ReadObject",
        "System.Runtime.Serialization.NetDataContractSerializer.Deserialize",
        "YamlDotNet.Serialization.Deserializer.Deserialize",
        "MessagePack.MessagePackSerializer.Deserialize",
    };

    // ── Sinks de XXE (XML External Entity) ────────────────────────────────────
    public static readonly HashSet<string> XxeSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Xml.XmlDocument.Load",
        "System.Xml.XmlDocument.LoadXml",
        "System.Xml.XmlTextReader..ctor",
        "System.Xml.XmlReader.Create",
        "System.Xml.Linq.XDocument.Load",
        "System.Xml.Linq.XElement.Load",
        "System.Xml.XPath.XPathDocument..ctor",
    };

    // ── Sinks de SSRF ─────────────────────────────────────────────────────────
    public static readonly HashSet<string> SsrfSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Net.Http.HttpClient.GetAsync",
        "System.Net.Http.HttpClient.PostAsync",
        "System.Net.Http.HttpClient.PutAsync",
        "System.Net.Http.HttpClient.DeleteAsync",
        "System.Net.Http.HttpClient.SendAsync",
        "System.Net.WebClient.DownloadString",
        "System.Net.WebClient.DownloadData",
        "System.Net.WebRequest.Create",
        "System.Net.Http.HttpClient.GetStringAsync",
        "RestSharp.RestClient.ExecuteAsync",
    };

    // ── Sinks de Reflection Abuse ─────────────────────────────────────────────
    public static readonly HashSet<string> ReflectionSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Reflection.Assembly.Load",
        "System.Reflection.Assembly.LoadFrom",
        "System.Reflection.Assembly.LoadFile",
        "System.Activator.CreateInstance",
        "System.Type.GetType",
        "System.Reflection.MethodInfo.Invoke",
    };

    // ── Sinks de Razor/XSS ────────────────────────────────────────────────────
    public static readonly HashSet<string> RazorXssSinks = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.AspNetCore.Html.HtmlString..ctor",
        "Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperExtensions.Raw",
        "System.Web.HtmlString..ctor",
        "System.Web.Mvc.HtmlHelper.Raw",
    };

    /// <summary>
    /// Todos los sinks conocidos en un solo conjunto para búsqueda O(1).
    /// Usado por SemanticExtractor para preclasificar nodos.
    /// </summary>
    public static readonly HashSet<string> AllSinks = new(
        SqlSinks
            .Concat(CommandSinks)
            .Concat(PathSinks)
            .Concat(DeserializationSinks)
            .Concat(XxeSinks)
            .Concat(SsrfSinks)
            .Concat(ReflectionSinks)
            .Concat(RazorXssSinks),
        StringComparer.OrdinalIgnoreCase
    );

    // ── Sources conocidas ─────────────────────────────────────────────────────

    /// <summary>
    /// Símbolos que representan entradas controladas por el atacante.
    /// El engine Python completa este catálogo con reglas de framework.
    /// </summary>
    public static readonly HashSet<string> KnownSources = new(StringComparer.OrdinalIgnoreCase)
    {
        // ASP.NET Core
        "Microsoft.AspNetCore.Http.IQueryCollection",
        "Microsoft.AspNetCore.Http.IFormCollection",
        "Microsoft.AspNetCore.Http.IHeaderDictionary",
        "Microsoft.AspNetCore.Http.HttpRequest.QueryString",
        "Microsoft.AspNetCore.Http.HttpRequest.Form",
        "Microsoft.AspNetCore.Http.HttpRequest.Headers",
        "Microsoft.AspNetCore.Http.HttpRequest.Body",
        "Microsoft.AspNetCore.Http.HttpRequest.Path",
        "Microsoft.AspNetCore.Routing.RouteData.Values",

        // ASP.NET MVC clásico
        "System.Web.HttpRequest.QueryString",
        "System.Web.HttpRequest.Form",
        "System.Web.HttpRequest.Headers",
        "System.Web.HttpRequest.Cookies",
        "System.Web.HttpRequest.ServerVariables",
        "System.Web.HttpRequest.InputStream",

        // Console (para tools/CLI analizadas)
        "System.Console.ReadLine",
        "System.Console.In",
        "System.Environment.GetCommandLineArgs",
    };

    // ── Sanitizadores conocidos ───────────────────────────────────────────────

    /// <summary>
    /// Símbolos que sanitizan/codifican datos, interrumpiendo flujos taint.
    /// </summary>
    public static readonly HashSet<string> KnownSanitizers = new(StringComparer.OrdinalIgnoreCase)
    {
        // SQL — parameterization
        "System.Data.SqlClient.SqlParameter..ctor",
        "Microsoft.Data.SqlClient.SqlParameter..ctor",

        // HTML encoding
        "System.Net.WebUtility.HtmlEncode",
        "System.Web.HttpUtility.HtmlEncode",
        "System.Text.Encodings.Web.HtmlEncoder.Encode",
        "Microsoft.Security.Application.Encoder.HtmlEncode",

        // URL encoding
        "System.Net.WebUtility.UrlEncode",
        "System.Web.HttpUtility.UrlEncode",
        "System.Uri.EscapeDataString",

        // Path sanitization
        "System.IO.Path.GetFileName",          // elimina componentes de directorio
        "System.IO.Path.GetFullPath",          // resuelve traversals

        // XML safe readers
        "System.Xml.XmlReader.Create",         // safe cuando se pasa XmlReaderSettings con DtdProcessing.Prohibit

        // Validation
        "System.Text.RegularExpressions.Regex.IsMatch",
        "System.Int32.TryParse",
        "System.Guid.TryParse",
    };

    /// <summary>
    /// Determina si un símbolo resuelto es un sink conocido.
    /// Busca por prefijo para cubrir sobrecargas del mismo método.
    /// </summary>
    public static bool IsSink(string? resolvedSymbol)
    {
        if (resolvedSymbol is null) return false;
        return AllSinks.Any(s => resolvedSymbol.StartsWith(s, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determina si un símbolo resuelto es una source conocida.
    /// </summary>
    public static bool IsSource(string? resolvedSymbol)
    {
        if (resolvedSymbol is null) return false;
        return KnownSources.Any(s => resolvedSymbol.StartsWith(s, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determina si un símbolo resuelto es un sanitizador conocido.
    /// </summary>
    public static bool IsSanitizer(string? resolvedSymbol)
    {
        if (resolvedSymbol is null) return false;
        return KnownSanitizers.Any(s => resolvedSymbol.StartsWith(s, StringComparison.OrdinalIgnoreCase));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXTENSIONES DE SemanticNode (record del ExportSchema)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Métodos de extensión sobre SemanticNode (el record del ExportSchema).
/// Permiten consultas de dominio SAST sin contaminar el DTO puro.
/// </summary>
public static class SemanticNodeExtensions
{
    /// <summary>
    /// true si este nodo es un sink conocido según el catálogo interno del bridge.
    /// El engine Python realiza la clasificación definitiva; esto es una
    /// optimización para filtrar nodos antes de la serialización.
    /// </summary>
    public static bool IsKnownSink(this SemanticNode node) =>
        KnownSastSymbols.IsSink(node.ResolvedSymbol);

    /// <summary>
    /// true si este nodo es una source conocida de input del atacante.
    /// </summary>
    public static bool IsKnownSource(this SemanticNode node) =>
        KnownSastSymbols.IsSource(node.ResolvedSymbol);

    /// <summary>
    /// true si este nodo es un sanitizador conocido.
    /// </summary>
    public static bool IsKnownSanitizer(this SemanticNode node) =>
        KnownSastSymbols.IsSanitizer(node.ResolvedSymbol);

    /// <summary>
    /// true si algún argumento del nodo tiene origen no literal.
    /// Un nodo sink con todos los argumentos literales no es vulnerable.
    /// </summary>
    public static bool HasNonLiteralArguments(this SemanticNode node) =>
        node.Arguments.Any(a => !a.IsLiteral);

    /// <summary>
    /// true si algún argumento tiene origen "parameter" o "return_value".
    /// Estos son los argumentos que el taint analyzer debe rastrear.
    /// </summary>
    public static bool HasPotentiallyTaintedArguments(this SemanticNode node) =>
        node.Arguments.Any(a =>
            a.DataFlowOrigin is "parameter" or "return_value" or "local_variable");

    /// <summary>
    /// Devuelve los argumentos que son candidatos a estar tainted.
    /// </summary>
    public static IEnumerable<ArgumentExport> GetPotentiallyTaintedArguments(this SemanticNode node) =>
        node.Arguments.Where(a =>
            a.DataFlowOrigin is "parameter" or "return_value" or "local_variable");

    /// <summary>
    /// Determina la prioridad de análisis del nodo (1=alta, 3=baja).
    /// El engine Python puede usar esto para ordenar el análisis.
    /// </summary>
    public static int GetAnalysisPriority(this SemanticNode node)
    {
        if (node.IsKnownSink() && node.HasPotentiallyTaintedArguments())
            return 1;  // Sink con argumentos sospechosos → analizar primero

        if (node.IsKnownSink() || node.IsKnownSource())
            return 2;  // Sink o source sin match inmediato

        return 3;       // Nodo de contexto general
    }
}

/// <summary>
/// Extensiones sobre ArgumentExport para consultas de dominio.
/// </summary>
public static class ArgumentExportExtensions
{
    /// <summary>
    /// true si el argumento puede contener input del atacante
    /// basándose en su DataFlowOrigin.
    /// </summary>
    public static bool MayBeTainted(this ArgumentExport arg) =>
        !arg.IsLiteral && arg.DataFlowOrigin is "parameter" or "return_value" or "unknown";

    /// <summary>
    /// Convierte el string DataFlowOrigin al enum tipado DataFlowOriginKind.
    /// </summary>
    public static DataFlowOriginKind GetOriginKind(this ArgumentExport arg) =>
        arg.DataFlowOrigin switch
        {
            "parameter"      => DataFlowOriginKind.Parameter,
            "field"          => DataFlowOriginKind.Field,
            "local_variable" => DataFlowOriginKind.LocalVariable,
            "return_value"   => DataFlowOriginKind.ReturnValue,
            "literal"        => DataFlowOriginKind.Literal,
            _                => DataFlowOriginKind.Unknown,
        };
}

// ─────────────────────────────────────────────────────────────────────────────
//  BUILDER INTERNO — CONSTRUCCIÓN FLUIDA DE SemanticNode
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Builder que facilita la construcción de SemanticNode en los extractores,
/// evitando la necesidad de pasar todos los parámetros en un solo constructor.
/// Se usa dentro del bridge (no se exporta al JSON).
/// </summary>
public sealed class SemanticNodeBuilder
{
    private string _nodeId      = Guid.NewGuid().ToString("N");
    private string _kind        = SemanticNodeKind.InvocationExpression.ToString();
    private string _text        = string.Empty;
    private string _file        = string.Empty;
    private int    _line;
    private int    _column;
    private string? _resolvedSymbol;
    private string? _resolvedType;
    private string? _containingMethodId;
    private string? _containingClassId;
    private List<ArgumentExport> _arguments = [];
    private bool   _isAsyncCall;
    private bool   _isInTryBlock;
    private List<string> _parentContext = [];

    public SemanticNodeBuilder WithKind(SemanticNodeKind kind)
    {
        _kind = kind.ToString();
        return this;
    }

    public SemanticNodeBuilder WithText(string text, int maxLength = 200)
    {
        _text = text.Length <= maxLength ? text : text[..maxLength] + "…";
        return this;
    }

    public SemanticNodeBuilder WithLocation(string file, int line, int column)
    {
        _file   = file;
        _line   = line;
        _column = column;
        return this;
    }

    public SemanticNodeBuilder WithResolvedSymbol(string? symbol)
    {
        _resolvedSymbol = symbol;
        return this;
    }

    public SemanticNodeBuilder WithResolvedType(string? type)
    {
        _resolvedType = type;
        return this;
    }

    public SemanticNodeBuilder WithContainingMethod(string? methodId)
    {
        _containingMethodId = methodId;
        return this;
    }

    public SemanticNodeBuilder WithContainingClass(string? classId)
    {
        _containingClassId = classId;
        return this;
    }

    public SemanticNodeBuilder WithArguments(IEnumerable<ArgumentExport> arguments)
    {
        _arguments = arguments.ToList();
        return this;
    }

    public SemanticNodeBuilder IsAsync(bool isAsync = true)
    {
        _isAsyncCall = isAsync;
        return this;
    }

    public SemanticNodeBuilder IsInTry(bool isInTry = true)
    {
        _isInTryBlock = isInTry;
        return this;
    }

    public SemanticNodeBuilder WithParentContext(IEnumerable<string> context)
    {
        _parentContext = context.ToList();
        return this;
    }

    public SemanticNode Build() => new(
        NodeId:             _nodeId,
        Kind:               _kind,
        Text:               _text,
        File:               _file,
        Line:               _line,
        Column:             _column,
        ResolvedSymbol:     _resolvedSymbol,
        ResolvedType:       _resolvedType,
        ContainingMethodId: _containingMethodId,
        ContainingClassId:  _containingClassId,
        Arguments:          _arguments,
        IsAsyncCall:        _isAsyncCall,
        IsInTryBlock:       _isInTryBlock,
        ParentContext:      _parentContext
    );
}