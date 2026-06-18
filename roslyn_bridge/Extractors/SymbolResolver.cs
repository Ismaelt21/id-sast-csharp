// =============================================================================
//  csharp-sast / roslyn_bridge / Extractors / SymbolResolver.cs
// =============================================================================
//
//  RESOLUCIÓN DE SÍMBOLOS EXTERNOS
//  ─────────────────────────────────
//  Resuelve símbolos que van más allá del código analizado:
//    • Tipos de librerías NuGet (Dapper, Newtonsoft.Json, etc.)
//    • Tipos del framework ASP.NET Core
//    • Tipos del BCL de .NET (System.IO, System.Data, etc.)
//    • Herencia: si un método hereda de SqlCommand, sigue siendo un sink
//    • Interfaces: IDbCommand.ExecuteNonQuery() → potencial SQL injection
//
//  POR QUÉ ES CRÍTICO:
//    Sin resolución de símbolos externos el engine solo puede analizar código
//    que usa los tipos exactos del catálogo.
//
//    Ejemplo del problema sin SymbolResolver:
//      public class MySafeCommand : SqlCommand { }    // hereda de SqlCommand
//      new MySafeCommand(userInput)                   // ¿sink? SÍ, pero el
//                                                     // nombre no está en el catálogo
//
//    Con SymbolResolver:
//      MySafeCommand.BaseType = SqlCommand            // detectado como sink
//      MySafeCommand implementa IDbCommand            // detectado vía interfaz
//
//  ESTRATEGIA:
//    1. Resolución directa: el símbolo está en el catálogo
//    2. Resolución por herencia: el tipo hereda de un tipo sink
//    3. Resolución por interfaz: el tipo implementa una interfaz sink
//    4. Resolución por NuGet: el assembly es un paquete NuGet conocido
//    5. Cache: los símbolos resueltos se cachean para evitar consultas repetidas
//
// =============================================================================

using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using RoslynBridge.Models;

namespace RoslynBridge.Extractors;

/// <summary>
/// Resuelve y enriquece la información de símbolos externos.
/// Se usa en SemanticExtractor y DfgExtractor para mejorar
/// la precisión de la resolución de sinks, sources y sanitizadores.
/// </summary>
public sealed class SymbolResolver
{
    private readonly ILogger<SymbolResolver> _logger;

    // Cache de resolución para evitar consultas repetidas al SemanticModel.
    // ConcurrentDictionary porque SemanticExtractor procesa archivos en paralelo.
    private readonly ConcurrentDictionary<string, ResolvedSymbolInfo> _cache = new();

    // Cache de jerarquía de tipos (herencia e interfaces)
    private readonly ConcurrentDictionary<string, IReadOnlyList<string>> _hierarchyCache = new();

    public SymbolResolver(ILogger<SymbolResolver> logger)
    {
        _logger = logger;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  RESOLUCIÓN PRINCIPAL
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Resuelve la información completa de un símbolo dado su nombre de metadata.
    /// </summary>
    /// <param name="resolvedSymbol">
    /// Nombre de metadata del símbolo (formato Roslyn FullyQualified):
    ///   "System.Data.SqlClient.SqlCommand..ctor"
    /// </param>
    /// <param name="symbol">El ISymbol de Roslyn si está disponible.</param>
    /// <returns>Información enriquecida del símbolo.</returns>
    public ResolvedSymbolInfo Resolve(string? resolvedSymbol, ISymbol? symbol = null)
    {
        if (resolvedSymbol is null)
            return ResolvedSymbolInfo.Unknown;

        return _cache.GetOrAdd(resolvedSymbol, key => BuildSymbolInfo(key, symbol));
    }

    /// <summary>
    /// Resuelve la jerarquía de tipos de un INamedTypeSymbol.
    /// Retorna todos los nombres de metadata de los tipos en la jerarquía:
    ///   MiClase → BaseClass → SqlCommand → System.Object
    /// </summary>
    public IReadOnlyList<string> ResolveTypeHierarchy(INamedTypeSymbol? typeSymbol)
    {
        if (typeSymbol is null) return [];

        var key = typeSymbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        return _hierarchyCache.GetOrAdd(key, _ =>
        {
            var hierarchy = new List<string>();
            CollectHierarchy(typeSymbol, hierarchy, new HashSet<string>());
            return hierarchy;
        });
    }

    /// <summary>
    /// Determina si un tipo (o alguno de sus ancestros/interfaces) es un sink conocido.
    /// Este es el método principal usado por SemanticExtractor para la resolución
    /// por herencia e interfaz.
    /// </summary>
    public bool IsSinkByHierarchy(INamedTypeSymbol? typeSymbol)
    {
        if (typeSymbol is null) return false;

        var hierarchy = ResolveTypeHierarchy(typeSymbol);
        return hierarchy.Any(typeName =>
            KnownSastSymbols.AllSinks.Any(sink =>
                typeName.StartsWith(sink, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Determina si un método (incluyendo su tipo contenedor y sus ancestros)
    /// coincide con algún sink del catálogo.
    ///
    /// Orden de verificación:
    ///   1. Coincidencia directa del símbolo resuelto
    ///   2. Tipo contenedor en la jerarquía de herencia
    ///   3. Interfaces implementadas por el tipo contenedor
    /// </summary>
    public bool IsSinkMethod(IMethodSymbol? methodSymbol)
    {
        if (methodSymbol is null) return false;

        var directSymbol = methodSymbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        // 1. Coincidencia directa
        if (KnownSastSymbols.IsSink(directSymbol)) return true;

        // 2. Por jerarquía del tipo contenedor
        if (methodSymbol.ContainingType is not null)
        {
            var hierarchy = ResolveTypeHierarchy(methodSymbol.ContainingType);
            foreach (var ancestorType in hierarchy)
            {
                // Reconstruir el nombre del método con el tipo ancestro
                var ancestorMethodName = $"{ancestorType}.{methodSymbol.Name}";
                if (KnownSastSymbols.IsSink(ancestorMethodName)) return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determina si un método es una source de input del atacante
    /// usando resolución por jerarquía.
    /// </summary>
    public bool IsSourceMethod(IMethodSymbol? methodSymbol)
    {
        if (methodSymbol is null) return false;

        var directSymbol = methodSymbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        if (KnownSastSymbols.IsSource(directSymbol)) return true;

        if (methodSymbol.ContainingType is not null)
        {
            var hierarchy = ResolveTypeHierarchy(methodSymbol.ContainingType);
            return hierarchy.Any(t =>
                KnownSastSymbols.KnownSources.Any(s =>
                    s.StartsWith(t, StringComparison.OrdinalIgnoreCase)));
        }

        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  RESOLUCIÓN DE INFORMACIÓN DE ASSEMBLY / NUGET
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Identifica el paquete NuGet al que pertenece un assembly.
    /// Importante para detectar ORMs y clientes HTTP no estándar.
    /// </summary>
    public NugetPackageInfo? ResolveNugetPackage(string assemblyName)
    {
        return KnownNugetAssemblies.TryGetValue(assemblyName, out var info) ? info : null;
    }

    /// <summary>
    /// Resuelve si un tipo implementa IDisposable correctamente.
    /// Útil para detectar resource leaks que pueden ser explotados.
    /// </summary>
    public bool ImplementsIDisposable(INamedTypeSymbol? typeSymbol)
    {
        if (typeSymbol is null) return false;

        return typeSymbol.AllInterfaces.Any(i =>
            i.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
             .Equals("global::System.IDisposable", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Resuelve la versión de C# a partir del LanguageVersion de Roslyn.
    /// </summary>
    public static string ResolveLanguageVersionString(Microsoft.CodeAnalysis.CSharp.LanguageVersion version) =>
        version switch
        {
            Microsoft.CodeAnalysis.CSharp.LanguageVersion.CSharp12 => "CSharp12",
            Microsoft.CodeAnalysis.CSharp.LanguageVersion.CSharp11 => "CSharp11",
            Microsoft.CodeAnalysis.CSharp.LanguageVersion.CSharp10 => "CSharp10",
            Microsoft.CodeAnalysis.CSharp.LanguageVersion.CSharp9  => "CSharp9",
            Microsoft.CodeAnalysis.CSharp.LanguageVersion.CSharp8  => "CSharp8",
            Microsoft.CodeAnalysis.CSharp.LanguageVersion.Preview   => "CSharp13Preview",
            _                                                        => "Latest",
        };

    // ─────────────────────────────────────────────────────────────────────────
    //  RESOLUCIÓN DE TIPOS DE FRAMEWORK
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Determina si un tipo es un controller de ASP.NET Core.
    /// Los controllers son entry points de la aplicación y sus parámetros
    /// de action methods son fuentes de input del atacante.
    /// </summary>
    public bool IsAspNetController(INamedTypeSymbol? typeSymbol)
    {
        if (typeSymbol is null) return false;

        // Verificar atributos de controlador
        var attrs = typeSymbol.GetAttributes()
            .Select(a => a.AttributeClass?.Name ?? "")
            .ToHashSet();

        if (attrs.Any(a => a is "ApiControllerAttribute" or "ControllerAttribute"))
            return true;

        // Verificar herencia de ControllerBase o Controller
        var hierarchy = ResolveTypeHierarchy(typeSymbol);
        return hierarchy.Any(t =>
            t.Contains("Microsoft.AspNetCore.Mvc.ControllerBase") ||
            t.Contains("Microsoft.AspNetCore.Mvc.Controller") ||
            t.Contains("System.Web.Mvc.Controller"));
    }

    /// <summary>
    /// Determina si un método es un action method de ASP.NET.
    /// Los action methods son entry points de HTTP requests.
    /// </summary>
    public bool IsActionMethod(IMethodSymbol? methodSymbol)
    {
        if (methodSymbol is null) return false;

        var attrs = methodSymbol.GetAttributes()
            .Select(a => a.AttributeClass?.Name ?? "")
            .ToHashSet();

        return attrs.Any(a => a is
            "HttpGetAttribute" or "HttpPostAttribute" or "HttpPutAttribute" or
            "HttpDeleteAttribute" or "HttpPatchAttribute" or "RouteAttribute" or
            "ActionNameAttribute");
    }

    /// <summary>
    /// Determina si un parámetro recibe su valor de la HTTP request.
    /// Los parámetros marcados con [FromQuery], [FromBody], [FromRoute], [FromForm]
    /// son fuentes de input del atacante en ASP.NET Core.
    /// </summary>
    public bool IsHttpBoundParameter(IParameterSymbol? paramSymbol)
    {
        if (paramSymbol is null) return false;

        var bindingAttrs = paramSymbol.GetAttributes()
            .Select(a => a.AttributeClass?.Name ?? "")
            .ToHashSet();

        // Atributos explícitos de binding
        if (bindingAttrs.Any(a => a is
            "FromQueryAttribute" or "FromBodyAttribute" or "FromRouteAttribute" or
            "FromFormAttribute" or "FromHeaderAttribute" or "FromServicesAttribute"))
            return true;

        // En ASP.NET Core los parámetros simples de action methods sin atributo
        // también se bindean desde query string o route por convención.
        var isSimpleType = paramSymbol.Type.SpecialType is
            SpecialType.System_String or 
            SpecialType.System_Int32 or
            SpecialType.System_Int64 or 
            SpecialType.System_Boolean
            ||
            (paramSymbol.Type.Name == "Guid" &&
            paramSymbol.Type.ContainingNamespace?.ToDisplayString() == "System");
        return isSimpleType && IsActionMethod(paramSymbol.ContainingSymbol as IMethodSymbol);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  RESOLUCIÓN DE INTERPOLATED STRINGS (riesgo SQL/Command Injection)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Determina si un símbolo de tipo string es construido mediante interpolación.
    /// Las cadenas interpoladas con parámetros son vectores de SQL injection:
    ///   $"SELECT * FROM Users WHERE id = {userId}"  → VULNERABLE
    /// </summary>
    public static bool IsInterpolatedStringWithExternalData(
        Microsoft.CodeAnalysis.CSharp.Syntax.InterpolatedStringExpressionSyntax? interpolation,
        SemanticModel semanticModel)
    {
        if (interpolation is null) return false;

        // Verificar si alguna de las interpolaciones tiene origen externo
        return interpolation.Contents
            .OfType<Microsoft.CodeAnalysis.CSharp.Syntax.InterpolationSyntax>()
            .Any(part =>
            {
                var symbolInfo = semanticModel.GetSymbolInfo(part.Expression);
                var symbol     = symbolInfo.Symbol;

                // Si el símbolo es un parámetro del método → potencial injection
                return symbol is IParameterSymbol or ILocalSymbol;
            });
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS PRIVADOS
    // ─────────────────────────────────────────────────────────────────────────

    private ResolvedSymbolInfo BuildSymbolInfo(string resolvedSymbol, ISymbol? symbol)
    {
        var isSink       = KnownSastSymbols.IsSink(resolvedSymbol);
        var isSource     = KnownSastSymbols.IsSource(resolvedSymbol);
        var isSanitizer  = KnownSastSymbols.IsSanitizer(resolvedSymbol);

        string? assemblyName = null;
        string? nugetPackage = null;

        if (symbol?.ContainingAssembly is not null)
        {
            assemblyName = symbol.ContainingAssembly.Name;
            var nugetInfo = ResolveNugetPackage(assemblyName);
            nugetPackage  = nugetInfo?.PackageName;

            // Si el símbolo directo no es un sink, verificar por jerarquía
            if (!isSink && symbol is IMethodSymbol methodSymbol)
                isSink = IsSinkMethod(methodSymbol);
        }

        var classification = (isSink, isSource, isSanitizer) switch
        {
            (true,  _,    _   ) => SymbolClassification.Sink,
            (_,     true, _   ) => SymbolClassification.Source,
            (_,     _,    true) => SymbolClassification.Sanitizer,
            _                   => SymbolClassification.Unknown,
        };

        return new ResolvedSymbolInfo(
            FullName:       resolvedSymbol,
            Classification: classification,
            Assembly:       assemblyName,
            NugetPackage:   nugetPackage,
            IsSink:         isSink,
            IsSource:       isSource,
            IsSanitizer:    isSanitizer
        );
    }

    private static void CollectHierarchy(
        INamedTypeSymbol typeSymbol,
        List<string> result,
        HashSet<string> visited)
    {
        var fullName = typeSymbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        if (!visited.Add(fullName)) return;

        result.Add(fullName);

        // Recorrer jerarquía de herencia
        if (typeSymbol.BaseType is not null && typeSymbol.BaseType.SpecialType != SpecialType.System_Object)
            CollectHierarchy(typeSymbol.BaseType, result, visited);

        // Recorrer interfaces implementadas
        foreach (var iface in typeSymbol.Interfaces)
            CollectHierarchy(iface, result, visited);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  CATÁLOGO DE ASSEMBLIES NUGET CONOCIDOS
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Mapa de nombre de assembly → información del paquete NuGet.
    /// Permite al engine Python enriquecer el contexto de los sinks
    /// con el nombre del paquete (útil para los reportes).
    /// </summary>
    private static readonly Dictionary<string, NugetPackageInfo> KnownNugetAssemblies =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // ORMs y data access
            ["Dapper"]                  = new("Dapper",                  ">=1.50",  RiskLevel.High),
            ["Dapper.Contrib"]          = new("Dapper.Contrib",          ">=1.0",   RiskLevel.Medium),
            ["NPoco"]                   = new("NPoco",                   ">=4.0",   RiskLevel.High),
            ["PetaPoco"]                = new("PetaPoco",                ">=6.0",   RiskLevel.High),
            ["ServiceStack.OrmLite"]    = new("ServiceStack.OrmLite",    ">=6.0",   RiskLevel.High),

            // Serialización
            ["Newtonsoft.Json"]         = new("Newtonsoft.Json",         ">=13.0",  RiskLevel.Medium),
            ["YamlDotNet"]              = new("YamlDotNet",              ">=13.0",  RiskLevel.High),
            ["MessagePack"]             = new("MessagePack",             ">=2.5",   RiskLevel.High),
            ["protobuf-net"]            = new("protobuf-net",            ">=3.0",   RiskLevel.Low),

            // HTTP clients
            ["RestSharp"]               = new("RestSharp",               ">=110.0", RiskLevel.Medium),
            ["Flurl.Http"]              = new("Flurl.Http",              ">=3.0",   RiskLevel.Medium),
            ["Refit"]                   = new("Refit",                   ">=7.0",   RiskLevel.Medium),

            // Templating (XSS risk)
            ["RazorEngine"]             = new("RazorEngine",             ">=3.10",  RiskLevel.High),
            ["Scriban"]                 = new("Scriban",                 ">=5.0",   RiskLevel.Medium),

            // Logging (log injection risk)
            ["Serilog"]                 = new("Serilog",                 ">=3.0",   RiskLevel.Low),
            ["NLog"]                    = new("NLog",                    ">=5.0",   RiskLevel.Low),
            ["log4net"]                 = new("log4net",                 ">=2.0",   RiskLevel.Low),

            // Excel/CSV (XXE risk en formatos XML)
            ["DocumentFormat.OpenXml"]  = new("DocumentFormat.OpenXml",  ">=3.0",   RiskLevel.Medium),
            ["ClosedXML"]               = new("ClosedXML",               ">=0.102", RiskLevel.Low),
            ["CsvHelper"]               = new("CsvHelper",               ">=30.0",  RiskLevel.Low),

            // SSH/SFTP (command injection risk)
            ["SSH.NET"]                 = new("SSH.NET",                 ">=2023.0", RiskLevel.High),
            ["Renci.SshNet"]            = new("Renci.SshNet",            ">=2023.0", RiskLevel.High),

            // AWS/Azure SDKs (SSRF risk)
            ["AWSSDK.Core"]             = new("AWSSDK.Core",             ">=3.7",   RiskLevel.Medium),
            ["Azure.Core"]              = new("Azure.Core",              ">=1.35",  RiskLevel.Medium),
        };


    /// <summary>
    /// Normaliza el símbolo resuelto al formato fully qualified que espera el engine Python.
    /// Convierte "ReadAllText" → "System.IO.File.ReadAllText"
    /// usando el ISymbol disponible en el SemanticModel.
    /// 
    /// LLAMAR SIEMPRE DESDE SemanticExtractor antes de serializar el nodo.
    /// </summary>
    public static string NormalizeSymbol(ISymbol? symbol)
    {
        if (symbol is null)
            return string.Empty;

        // ToDisplayString con FullyQualifiedFormat produce:
        //   "global::System.IO.File.ReadAllText(string)"
        // Limpiamos el prefijo "global::" y la firma de parámetros
        // para obtener: "System.IO.File.ReadAllText"
        var full = symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        // Quitar "global::"
        if (full.StartsWith("global::", StringComparison.Ordinal))
            full = full["global::".Length..];

        // Para métodos: quitar la firma de parámetros "(string, bool...)"
        // Queremos el prefijo estable que usa el engine Python
        var parenIdx = full.IndexOf('(', StringComparison.Ordinal);
        if (parenIdx > 0)
            full = full[..parenIdx];

        return full;
    }
       
}

// ─────────────────────────────────────────────────────────────────────────────
//  MODELOS DE RESULTADO DE RESOLUCIÓN
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Información enriquecida de un símbolo resuelto.
/// Incluye clasificación SAST y metadatos de assembly/NuGet.
/// </summary>
public sealed record ResolvedSymbolInfo(
    string FullName,
    SymbolClassification Classification,
    string? Assembly,
    string? NugetPackage,
    bool IsSink,
    bool IsSource,
    bool IsSanitizer
)
{
    /// <summary>Instancia de símbolo no resuelto (null/unknown).</summary>
    public static readonly ResolvedSymbolInfo Unknown = new(
        FullName:       "unknown",
        Classification: SymbolClassification.Unknown,
        Assembly:       null,
        NugetPackage:   null,
        IsSink:         false,
        IsSource:       false,
        IsSanitizer:    false
    );

    /// <summary>
    /// true si el símbolo es relevante para el análisis SAST
    /// (sink, source o sanitizador).
    /// </summary>
    public bool IsRelevantForSast => IsSink || IsSource || IsSanitizer;
}

/// <summary>
/// Clasificación de un símbolo desde la perspectiva SAST.
/// </summary>
public enum SymbolClassification
{
    /// <summary>Destino de datos peligrosos (SqlCommand, Process.Start, etc.).</summary>
    Sink,

    /// <summary>Origen de input del atacante (HttpRequest, Console.ReadLine, etc.).</summary>
    Source,

    /// <summary>Transforma o valida datos, interrumpiendo el flujo taint.</summary>
    Sanitizer,

    /// <summary>Sin clasificación específica.</summary>
    Unknown,
}

/// <summary>Información de un paquete NuGet con relevancia SAST.</summary>
public sealed record NugetPackageInfo(
    string PackageName,
    string MinVersion,
    RiskLevel RiskLevel
);

/// <summary>Nivel de riesgo SAST asociado a un paquete NuGet.</summary>
public enum RiskLevel
{
    /// <summary>Alto riesgo: el paquete expone APIs inherentemente peligrosas.</summary>
    High,

    /// <summary>Riesgo medio: el paquete puede ser peligroso dependiendo del uso.</summary>
    Medium,

    /// <summary>Riesgo bajo: el paquete es generalmente seguro pero tiene algunos métodos riesgosos.</summary>
    Low,
}