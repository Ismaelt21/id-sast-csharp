// =============================================================================
//  csharp-sast / roslyn_bridge / Extractors / SemanticExtractor.cs
// =============================================================================
//
//  EXTRACTOR SEMÁNTICO PRINCIPAL — CORAZÓN DEL ROSLYN BRIDGE
//  ──────────────────────────────────────────────────────────
//  Recibe los archivos .cs, los compila en memoria con Roslyn y extrae:
//
//    1. Estructura estática (clases, métodos, propiedades, campos)
//    2. Nodos semánticos de interés SAST (invocaciones, creaciones de objetos)
//    3. Símbolos resueltos (nombres completos de metadata)
//    4. Información de flujo de datos en argumentos
//    5. Atributos relevantes para el análisis de framework
//
//  DIFERENCIA CLAVE CON ANÁLISIS SINTÁCTICO:
//    Sintáctico (Tree-sitter):   "SqlCommand" → texto encontrado
//    Semántico  (Roslyn):        "System.Data.SqlClient.SqlCommand..ctor"
//                                → símbolo resuelto, inmune a alias y herencia
//
//  PATRÓN DE DISEÑO:
//    SyntaxWalker — recorre el SyntaxTree nodo por nodo.
//    SemanticModel — se consulta en cada nodo para resolver símbolos.
//    No se mezclan responsabilidades: este archivo solo extrae,
//    no filtra por vulnerabilidades (eso es responsabilidad del engine Python).
//
// =============================================================================

using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using RoslynBridge.Models;

namespace RoslynBridge.Extractors;

/// <summary>
/// Orquesta la compilación en memoria y la extracción semántica completa.
/// Es el punto de entrada principal del bridge.
/// </summary>
public sealed class SemanticExtractor
{
    private readonly ILogger<SemanticExtractor> _logger;
    private readonly string _bridgeVersion;

    // Ensamblados de referencia del BCL de .NET 8 necesarios para resolver
    // símbolos de System.*, Microsoft.* sin un proyecto compilado real.
    private static readonly Lazy<IReadOnlyList<MetadataReference>> _defaultReferences =
        new(BuildDefaultReferences);

    public SemanticExtractor(ILogger<SemanticExtractor> logger)
    {
        _logger = logger;
        _bridgeVersion = typeof(SemanticExtractor).Assembly.GetName().Version?.ToString() ?? "1.0.0";
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  MÉTODO PRINCIPAL
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Extrae el modelo semántico completo de los archivos .cs proporcionados.
    /// </summary>
    /// <param name="request">Request con rutas de archivos y opciones.</param>
    /// <param name="cancellationToken">Token de cancelación para análisis largos.</param>
    /// <returns>RoslynExportRoot listo para serializar a JSON y enviar al engine Python.</returns>
    public async Task<RoslynExportRoot> ExtractAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Iniciando extracción semántica de {Count} archivo(s)", request.Files.Count);

        var startTime = DateTime.UtcNow;

        // ── 1. Cargar los archivos como SyntaxTrees ───────────────────────────
        var languageVersion = ParseLanguageVersion(request.LanguageVersion);
        var (syntaxTrees, loadErrors) = await LoadSyntaxTreesAsync(request.Files, languageVersion, cancellationToken);
        _logger.LogDebug("SyntaxTrees cargados: {Count}, errores: {Errors}", syntaxTrees.Count, loadErrors.Count);

        // ── 2. Construir la compilación en memoria ────────────────────────────
        var references = BuildReferences(request.ReferenceAssemblies);
        var compilation = BuildCompilation(syntaxTrees, references, languageVersion);

        // ── 3. Detectar framework y versión de C# ────────────────────────────
        var frameworkDetected = DetectFramework(compilation);
        var nugetRefs         = ExtractNugetReferences(compilation);
        var languageVersionStr = languageVersion.ToDisplayString();
        var treesInCompilation = compilation.SyntaxTrees.ToList();

        _logger.LogInformation("Framework detectado: {Framework}", frameworkDetected ?? "generic");

        // ── 4. Extraer estructura estática (clases y métodos) ─────────────────
        var allClasses = new List<ClassExport>();
        var allSemanticNodes = new ConcurrentBag<SemanticNode>();
        var allAssignments   = new ConcurrentBag<AssignmentExport>();
        var allParamFlows    = new ConcurrentBag<ParameterFlowExport>();
        var allReturnFlows   = new ConcurrentBag<ReturnFlowExport>();
        var allExternalCalls = new ConcurrentBag<ExternalCallExport>();
        var allAnnotations   = new ConcurrentBag<AttributeAnnotation>();

        // Recolectar usings de todos los archivos
        var allUsings     = new HashSet<string>();
        string? rootNamespace = null;

        // ── 5. Procesar cada SyntaxTree con su SemanticModel ─────────────────
        // El procesamiento es por archivo para aislar errores de compilación.
        // Se paraleliza con un límite de concurrencia para no saturar la CPU.
        var semaphore = new SemaphoreSlim(Environment.ProcessorCount);
        var tasks = treesInCompilation.Select(async tree =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                foreach (var t in compilation.SyntaxTrees)
                {
                    _logger.LogInformation(
                        "Compilation Tree: {Path}",
                        t.FilePath
                    );
                }

                _logger.LogInformation(
                    "Current Tree: {Path}",
                    tree.FilePath
                );

                if (!compilation.SyntaxTrees.Contains(tree))
                {
                    throw new Exception(
                        $"Tree {tree.FilePath} no pertenece a la compilación"
                    );
                }

                var semanticModel = compilation.GetSemanticModel(tree);
                var root          = await tree.GetRootAsync(cancellationToken);
                var filePath      = tree.FilePath;

                _logger.LogDebug("Procesando: {File}", filePath);

                // Usings
                var usings = root.DescendantNodes()
                    .OfType<UsingDirectiveSyntax>()
                    .Select(u => u.Name?.ToString())
                    .Where(u => u is not null)
                    .Cast<string>();
                lock (allUsings) { foreach (var u in usings) allUsings.Add(u); }

                // Namespace raíz (tomar el primero encontrado)
                lock(allClasses){
                    if (rootNamespace is null)
                    {
                        rootNamespace = 
                            root.DescendantNodes()
                                .OfType<NamespaceDeclarationSyntax>()
                                .Select(n => n.Name.ToString())
                                .FirstOrDefault()
                            
                             ?? root.DescendantNodes()
                                    .OfType<FileScopedNamespaceDeclarationSyntax>()
                                    .Select(n => n.Name.ToString())
                                    .FirstOrDefault();
                    }
                }
                

                // Clases
                var classVisitor = new ClassStructureVisitor(semanticModel, filePath);
                classVisitor.Visit(root);
                lock (allClasses) { allClasses.AddRange(classVisitor.Classes); }

                // Nodos semánticos de interés SAST
                var nodeVisitor = new SastNodeVisitor(
                    semanticModel, filePath, request.IncludeUnresolved,
                    classVisitor.MethodIdByPosition);
                nodeVisitor.Visit(root);

                foreach (var node in nodeVisitor.SemanticNodes)    allSemanticNodes.Add(node);
                foreach (var asgn in nodeVisitor.Assignments)       allAssignments.Add(asgn);
                foreach (var flow in nodeVisitor.ParameterFlows)    allParamFlows.Add(flow);
                foreach (var ret  in nodeVisitor.ReturnFlows)       allReturnFlows.Add(ret);
                foreach (var ext  in nodeVisitor.ExternalCalls)     allExternalCalls.Add(ext);
                foreach (var ann  in nodeVisitor.Annotations)       allAnnotations.Add(ann);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);

        // ── 6. Compilar errores de compilación (no fatales) ───────────────────
        var compilationErrors = BuildCompilationErrors(compilation, loadErrors);

        var elapsed = DateTime.UtcNow - startTime;
        _logger.LogInformation(
            "Extracción completada en {Elapsed:F2}s — {Nodes} nodos, {Classes} clases",
            elapsed.TotalSeconds, allSemanticNodes.Count, allClasses.Count);

        // ── 7. Ensamblar el resultado final ───────────────────────────────────
        return new RoslynExportRoot(
            Metadata: new ExportMetadata(
                Files:              request.Files,
                LanguageVersion:    languageVersionStr,
                FrameworkDetected:  frameworkDetected,
                NugetReferences:    nugetRefs,
                CompilationErrors:  compilationErrors,
                AnalysisTimestamp:  startTime.ToString("O"),
                BridgeVersion:      _bridgeVersion
            ),
            CompilationUnit: new CompilationUnit(
                Usings:        allUsings.OrderBy(u => u).ToList(),
                RootNamespace: rootNamespace,
                Classes:       allClasses
            ),
            SemanticNodes:  allSemanticNodes.OrderBy(n => n.File).ThenBy(n => n.Line).ToList(),
            ControlFlow:    new ControlFlowExport(Methods: []),  // Llenado por CfgExtractor
            DataFlow: new DataFlowExport(
                Assignments:    allAssignments.ToList(),
                ParameterFlows: allParamFlows.ToList(),
                ReturnFlows:    allReturnFlows.ToList()
            ),
            Symbols: new SymbolsExport(
                ExternalCalls:        allExternalCalls.ToList(),
                AttributeAnnotations: allAnnotations.ToList()
            )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  COMPILACIÓN EN MEMORIA
    // ─────────────────────────────────────────────────────────────────────────

    private static CSharpCompilation BuildCompilation(
        IReadOnlyList<SyntaxTree> trees,
        IReadOnlyList<MetadataReference> references,
        LanguageVersion languageVersion)
    {
        return CSharpCompilation.Create(
            assemblyName: "CSharpSastAnalysis",
            syntaxTrees:  trees,
            references:   references,
            options: new CSharpCompilationOptions(
                OutputKind.DynamicallyLinkedLibrary,
                // No emitir el binario — solo necesitamos el SemanticModel
                optimizationLevel: OptimizationLevel.Debug,
                // Permitir código con errores (código real puede ser incompleto)
                allowUnsafe:       false,
                nullableContextOptions: NullableContextOptions.Enable
            )
        );
    }

    private static async Task<(List<SyntaxTree>, List<CompilationErrorExport>)>
        LoadSyntaxTreesAsync(IReadOnlyList<string> files, LanguageVersion languageVersion, CancellationToken ct)
    {
        var trees = new List<SyntaxTree>();
        var errors = new List<CompilationErrorExport>();

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (!File.Exists(file))
                {
                    errors.Add(new CompilationErrorExport(file, 0,
                        $"Archivo no encontrado: {file}", "Error"));
                    continue;
                }

                var source = await File.ReadAllTextAsync(file, ct);
                var tree   = CSharpSyntaxTree.ParseText(
                    source,
                    new CSharpParseOptions(LanguageVersion.Latest),
                    path: file
                );
                trees.Add(tree);
            }
            catch (IOException ex)
            {
                errors.Add(new CompilationErrorExport(file, 0,
                    $"Error de lectura: {ex.Message}", "Error"));
            }
        }

        return (trees, errors);
    }

    private static List<MetadataReference> BuildReferences(IReadOnlyList<string>? customRefs)
    {
        var references = new List<MetadataReference>(_defaultReferences.Value);

        if (customRefs is not null)
        {
            foreach (var r in customRefs)
            {
                if (File.Exists(r))
                    references.Add(MetadataReference.CreateFromFile(r));
            }
        }

        return references;
    }

    /// <summary>
    /// Construye las referencias al BCL de .NET 8 necesarias para resolver
    /// System.*, Microsoft.* sin un proyecto compilado real.
    /// </summary>
    private static List<MetadataReference> BuildDefaultReferences()
    {
        var refs    = new List<MetadataReference>();
        var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;

        // Assemblies fundamentales para resolver la mayoría de tipos del BCL
        var coreAssemblies = new[]
        {
            "System.Private.CoreLib.dll",
            "System.Runtime.dll",
            "System.Collections.dll",
            "System.Linq.dll",
            "System.Threading.dll",
            "System.Threading.Tasks.dll",
            "System.IO.dll",
            "System.Net.Http.dll",
            "System.Private.Uri.dll",
            "System.Diagnostics.Process.dll",
            "System.Text.Json.dll",
            "System.Xml.dll",
            "System.Xml.Linq.dll",
            "System.Private.Xml.dll",
            "System.Private.Xml.Linq.dll",
            "System.Xml.XDocument.dll",
            "System.Xml.ReaderWriter.dll",
            "System.Data.Common.dll",
            "System.ComponentModel.dll",
            "System.ComponentModel.Annotations.dll",
            "System.ComponentModel.Primitives.dll",     
            "System.ComponentModel.TypeConverter.dll",    
            "System.Security.Cryptography.dll",
            "System.Diagnostics.DiagnosticSource.dll",    
            "System.Runtime.InteropServices.dll", 
            "netstandard.dll",
        };

        foreach (var asm in coreAssemblies)
        {
            var path = Path.Combine(runtimeDir, asm);
            if (File.Exists(path))
                refs.Add(MetadataReference.CreateFromFile(path));
        }

        // Microsoft.Data.SqlClient — reemplaza System.Data.SqlClient en .NET 8
        // Sin esta referencia los tipos SqlCommand/SqlConnection no se resuelven.
        var nugetPackagesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".nuget", "packages"
        );

        // Buscar Microsoft.Data.SqlClient en el cache NuGet local
        var sqlClientDirs = Directory.GetDirectories(
            Path.Combine(nugetPackagesDir, "microsoft.data.sqlclient"),
            "5.*",
            SearchOption.TopDirectoryOnly
        );

        if (sqlClientDirs.Length > 0)
        {
            var latestSqlClient = sqlClientDirs.OrderByDescending(d => d).First();
            // Buscar en net8.0 primero, luego netstandard2.0 como fallback
            var sqlClientDll =
                Directory.GetFiles(latestSqlClient, "Microsoft.Data.SqlClient.dll", SearchOption.AllDirectories)
                    .OrderByDescending(f => f.Contains("net8.0") ? 1 : 0)
                    .FirstOrDefault();

            if (sqlClientDll is not null)
            {
                refs.Add(MetadataReference.CreateFromFile(sqlClientDll));
                // También necesitamos Microsoft.Data.SqlClient.SNI para evitar
                // errores de tipos dependientes
            }
        }

        // ASP.NET Core — buscar en el directorio compartido de .NET
        var aspnetDir = Path.Combine(
            Path.GetDirectoryName(runtimeDir)!,
            "..", "..", "shared",
            "Microsoft.AspNetCore.App",
            "8.0.*"
        );

        var aspnetDirs = Directory.GetDirectories(
            Path.GetFullPath(Path.Combine(runtimeDir, "..", "..", "..", "shared",
                             "Microsoft.AspNetCore.App")),
            "8.*",
            SearchOption.TopDirectoryOnly
        );

        if (aspnetDirs.Length > 0)
        {
            var latestAspnet = aspnetDirs.OrderByDescending(d => d).First();
            foreach (var dll in Directory.GetFiles(latestAspnet, "Microsoft.AspNetCore.*.dll"))
                refs.Add(MetadataReference.CreateFromFile(dll));
            foreach (var dll in Directory.GetFiles(latestAspnet, "Microsoft.Extensions.*.dll"))
                refs.Add(MetadataReference.CreateFromFile(dll));
        }

        return refs;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  DETECCIÓN DE FRAMEWORK
    // ─────────────────────────────────────────────────────────────────────────

    private static string? DetectFramework(CSharpCompilation compilation)
    {
        // Detectar por referencias de assembly presentes en la compilación
        var assemblyNames = compilation.ReferencedAssemblyNames
            .Select(a => a.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (assemblyNames.Any(a => a.StartsWith("Microsoft.AspNetCore.Mvc")))
            return "aspnetcore";
        if (assemblyNames.Any(a => a.StartsWith("System.ServiceModel")))
            return "wcf";
        if (assemblyNames.Any(a => a.StartsWith("System.Windows.Forms")))
            return "winforms";
        if (assemblyNames.Any(a => a.StartsWith("Microsoft.EntityFrameworkCore")))
            return "ef_core";
        if (assemblyNames.Any(a => a.StartsWith("System.Web")))
            return "aspnet_mvc";

        return null;
    }

    private static List<string> ExtractNugetReferences(CSharpCompilation compilation) =>
        compilation.ReferencedAssemblyNames
            .Select(a => $"{a.Name}/{a.Version}")
            .OrderBy(x => x)
            .ToList();

    private static LanguageVersion ParseLanguageVersion(string? version) =>
        version switch
        {
            "CSharp13" => LanguageVersion.Preview,
            "CSharp12" => LanguageVersion.CSharp12,
            "CSharp11" => LanguageVersion.CSharp11,
            "CSharp10" => LanguageVersion.CSharp10,
            "CSharp9"  => LanguageVersion.CSharp9,
            _          => LanguageVersion.Latest,
        };

    private static List<CompilationErrorExport> BuildCompilationErrors(
        CSharpCompilation compilation,
        List<CompilationErrorExport> loadErrors)
    {
        var errors = new List<CompilationErrorExport>(loadErrors);

        foreach (var diag in compilation.GetDiagnostics()
            .Where(d => d.Severity == DiagnosticSeverity.Error))
        {
            var loc = diag.Location.GetLineSpan();
            errors.Add(new CompilationErrorExport(
                File:     loc.Path,
                Line:     loc.StartLinePosition.Line + 1,
                Message:  diag.GetMessage(),
                Severity: "Error"
            ));
        }

        return errors;
    }
}

// =============================================================================
//  SYNTAX WALKERS — VISITAN EL ÁRBOL DE SINTAXIS EXTRAYENDO INFORMACIÓN
// =============================================================================

/// <summary>
/// Walker que extrae la estructura estática del código:
/// clases, métodos, propiedades y campos con sus metadatos semánticos.
/// </summary>
internal sealed class ClassStructureVisitor : CSharpSyntaxWalker
{
    private readonly SemanticModel _semanticModel;
    private readonly string _filePath;

    public List<ClassExport> Classes { get; } = [];

    /// <summary>
    /// Mapa de posición en el SyntaxTree → method_id.
    /// Usado por SastNodeVisitor para asignar containing_method_id a cada nodo.
    /// </summary>
    public Dictionary<(int Start, int End), string> MethodIdByPosition { get; } = [];

    public ClassStructureVisitor(SemanticModel semanticModel, string filePath)
        : base(SyntaxWalkerDepth.Node)
    {
        _semanticModel = semanticModel;
        _filePath      = filePath;
    }

    public override void VisitClassDeclaration(ClassDeclarationSyntax node)
    {
        var symbol = _semanticModel.GetDeclaredSymbol(node) as INamedTypeSymbol;
        if (symbol is null) { base.VisitClassDeclaration(node); return; }

        var classId = Guid.NewGuid().ToString("N");
        var methods = ExtractMethods(node, classId);
        var cls     = BuildClassExport(node, symbol, classId, methods, "class");
        Classes.Add(cls);

        base.VisitClassDeclaration(node);
    }

    public override void VisitInterfaceDeclaration(InterfaceDeclarationSyntax node)
    {
        var symbol = _semanticModel.GetDeclaredSymbol(node) as INamedTypeSymbol;
        if (symbol is null) { base.VisitInterfaceDeclaration(node); return; }

        var classId = Guid.NewGuid().ToString("N");
        var methods = ExtractMethods(node, classId);
        var cls     = BuildClassExport(node, symbol, classId, methods, "interface");
        Classes.Add(cls);

        base.VisitInterfaceDeclaration(node);
    }

    public override void VisitRecordDeclaration(RecordDeclarationSyntax node)
    {
        var symbol = _semanticModel.GetDeclaredSymbol(node) as INamedTypeSymbol;
        if (symbol is null) { base.VisitRecordDeclaration(node); return; }

        var classId = Guid.NewGuid().ToString("N");
        var methods = ExtractMethods(node, classId);
        var cls     = BuildClassExport(node, symbol, classId, methods, "record");
        Classes.Add(cls);

        base.VisitRecordDeclaration(node);
    }

    // ── Extracción de métodos ─────────────────────────────────────────────────

    private List<MethodExport> ExtractMethods(SyntaxNode classNode, string classId)
    {
        var methods = new List<MethodExport>();

        foreach (var methodSyntax in classNode.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var symbol = _semanticModel.GetDeclaredSymbol(methodSyntax) as IMethodSymbol;
            if (symbol is null) continue;

            var methodId = Guid.NewGuid().ToString("N");
            var span     = methodSyntax.GetLocation().GetLineSpan();

            // Registrar posición → methodId para el SastNodeVisitor
            MethodIdByPosition[(methodSyntax.SpanStart, methodSyntax.Span.End)] = methodId;

            var isEntryPoint = IsEntryPointMethod(symbol);
            var parameters   = ExtractParameters(symbol);
            var attributes   = ExtractAttributeNames(symbol);

            methods.Add(new MethodExport(
                MethodId:          methodId,
                Name:              symbol.Name,
                Signature:         symbol.ToDisplayString(SymbolDisplayFormat.CSharpShortErrorMessageFormat),
                ReturnType:        symbol.ReturnType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                IsAsync:           symbol.IsAsync,
                IsStatic:          symbol.IsStatic,
                Accessibility:     symbol.DeclaredAccessibility.ToString().ToLowerInvariant(),
                Parameters:        parameters,
                Attributes:        attributes,
                File:              _filePath,
                LineStart:         span.StartLinePosition.Line + 1,
                LineEnd:           span.EndLinePosition.Line   + 1,
                IsEntryPoint:      isEntryPoint,
                ContainingClassId: classId
            ));
        }

        return methods;
    }

    private static bool IsEntryPointMethod(IMethodSymbol symbol)
    {
        var attrNames = symbol.GetAttributes()
            .Select(a => a.AttributeClass?.Name ?? "")
            .ToHashSet();

        // ASP.NET Core action methods
        if (attrNames.Any(a => a is "HttpGetAttribute" or "HttpPostAttribute"
                                  or "HttpPutAttribute" or "HttpDeleteAttribute"
                                  or "HttpPatchAttribute" or "RouteAttribute"))
            return true;

        // WCF OperationContract
        if (attrNames.Contains("OperationContractAttribute"))
            return true;

        return false;
    }

    private static List<ParameterExport> ExtractParameters(IMethodSymbol symbol) =>
        symbol.Parameters.Select((p, i) => new ParameterExport(
            Name:              p.Name,
            ResolvedType:      p.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
            Position:          i,
            HasDefault:        p.HasExplicitDefaultValue,
            BindingAttributes: p.GetAttributes()
                                .Select(a => a.AttributeClass?.Name ?? "")
                                .Where(a => !string.IsNullOrEmpty(a))
                                .ToList()
        )).ToList();

    private static List<string> ExtractAttributeNames(ISymbol symbol) =>
        symbol.GetAttributes()
              .Select(a => a.AttributeClass?.Name ?? "")
              .Where(a => !string.IsNullOrEmpty(a))
              .ToList();

    // ── Construcción de ClassExport ───────────────────────────────────────────

    private ClassExport BuildClassExport(
        SyntaxNode node,
        INamedTypeSymbol symbol,
        string classId,
        List<MethodExport> methods,
        string kind)
    {
        var loc   = node.GetLocation().GetLineSpan();
        var attrs = ExtractAttributeNames(symbol);

        var fields = symbol.GetMembers()
            .OfType<IFieldSymbol>()
            .Select(f => new FieldExport(
                Name:          f.Name,
                ResolvedType:  f.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                IsReadonly:    f.IsReadOnly,
                IsStatic:      f.IsStatic,
                Accessibility: f.DeclaredAccessibility.ToString().ToLowerInvariant()
            )).ToList();

        var properties = symbol.GetMembers()
            .OfType<IPropertySymbol>()
            .Select(p => new PropertyExport(
                Name:          p.Name,
                ResolvedType:  p.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                HasGetter:     p.GetMethod is not null,
                HasSetter:     p.SetMethod is not null,
                Accessibility: p.DeclaredAccessibility.ToString().ToLowerInvariant(),
                Attributes:    ExtractAttributeNames(p)
            )).ToList();

        return new ClassExport(
            ClassId:    classId,
            Name:       symbol.Name,
            FullName:   symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
            Kind:       kind,
            File:       _filePath,
            Line:       loc.StartLinePosition.Line + 1,
            BaseClass:  symbol.BaseType?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
            Interfaces: symbol.Interfaces.Select(i => i.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)).ToList(),
            Attributes: attrs,
            IsAbstract: symbol.IsAbstract,
            IsPartial:  symbol.DeclaringSyntaxReferences.Length > 1,
            Methods:    methods,
            Fields:     fields,
            Properties: properties
        );
    }
}

/// <summary>
/// Walker principal de análisis SAST.
/// Recorre el árbol buscando nodos de interés para la detección de vulnerabilidades:
/// invocaciones de métodos, creaciones de objetos, asignaciones, retornos.
///
/// Para cada nodo resuelve el símbolo con el SemanticModel de Roslyn,
/// obteniendo el nombre completo de metadata (no el texto del código).
/// </summary>
internal sealed class SastNodeVisitor : CSharpSyntaxWalker
{
    private readonly SemanticModel _semanticModel;
    private readonly string _filePath;
    private readonly bool _includeUnresolved;
    private readonly Dictionary<(int Start, int End), string> _methodIdByPosition;

    public List<SemanticNode>      SemanticNodes  { get; } = [];
    public List<AssignmentExport>  Assignments    { get; } = [];
    public List<ParameterFlowExport> ParameterFlows { get; } = [];
    public List<ReturnFlowExport>  ReturnFlows    { get; } = [];
    public List<ExternalCallExport> ExternalCalls { get; } = [];
    public List<AttributeAnnotation> Annotations  { get; } = [];

    public SastNodeVisitor(
        SemanticModel semanticModel,
        string filePath,
        bool includeUnresolved,
        Dictionary<(int Start, int End), string> methodIdByPosition)
        : base(SyntaxWalkerDepth.Node)
    {
        _semanticModel      = semanticModel;
        _filePath           = filePath;
        _includeUnresolved  = includeUnresolved;
        _methodIdByPosition = methodIdByPosition;
    }

    // ── Invocaciones de métodos ───────────────────────────────────────────────

    public override void VisitInvocationExpression(InvocationExpressionSyntax node)
    {
        var symbolInfo = _semanticModel.GetSymbolInfo(node);
        var symbol     = symbolInfo.Symbol as IMethodSymbol
                         ?? symbolInfo.CandidateSymbols.FirstOrDefault() as IMethodSymbol;

        var resolvedSymbol = symbol?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        if (!_includeUnresolved && resolvedSymbol is null)
        {
            base.VisitInvocationExpression(node);
            return;
        }

        var returnType = _semanticModel.GetTypeInfo(node).Type
            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        var containingMethodId = FindContainingMethodId(node);
        var containingClassId  = FindContainingClassId(node);
        var arguments          = ExtractArguments(node.ArgumentList.Arguments, containingMethodId);
        var isAsyncCall        = returnType?.StartsWith("System.Threading.Tasks.Task") == true
                                 || returnType?.StartsWith("System.Threading.Tasks.ValueTask") == true;

        var semanticNode = new SemanticNode(
            NodeId:             Guid.NewGuid().ToString("N"),
            Kind:               "InvocationExpression",
            Text:               TruncateText(node.ToString(), 200),
            File:               _filePath,
            Line:               node.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
            Column:             node.GetLocation().GetLineSpan().StartLinePosition.Character + 1,
            ResolvedSymbol:     resolvedSymbol,
            ResolvedType:       returnType,
            ContainingMethodId: containingMethodId,
            ContainingClassId:  containingClassId,
            Arguments:          arguments,
            IsAsyncCall:        isAsyncCall,
            IsInTryBlock:       IsInsideTryBlock(node),
            ParentContext:      GetParentContext(node)
        );

        SemanticNodes.Add(semanticNode);

        // Si el símbolo es externo (no está en los archivos analizados),
        // también lo registramos en ExternalCalls para el análisis de framework.
        if (symbol?.ContainingAssembly is not null
            && symbol.ContainingAssembly.Name != "CSharpSastAnalysis")
        {
            ExternalCalls.Add(new ExternalCallExport(
                NodeId:         semanticNode.NodeId,
                ResolvedSymbol: resolvedSymbol ?? node.ToString(),
                Assembly:       symbol.ContainingAssembly.Name,
                Line:           semanticNode.Line,
                File:           _filePath
            ));
        }

        base.VisitInvocationExpression(node);
    }

    // ── Creación de objetos (new T(...)) ──────────────────────────────────────

    public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
    {
        var symbolInfo     = _semanticModel.GetSymbolInfo(node);
        var symbol         = symbolInfo.Symbol as IMethodSymbol;
        var resolvedSymbol = symbol?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        if (!_includeUnresolved && resolvedSymbol is null)
        {
            base.VisitObjectCreationExpression(node);
            return;
        }

        var resolvedType = _semanticModel.GetTypeInfo(node).Type
            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        var containingMethodId = FindContainingMethodId(node);
        var containingClassId  = FindContainingClassId(node);
        var arguments = node.ArgumentList is not null
            ? ExtractArguments(node.ArgumentList.Arguments, containingMethodId)
            : [];

        SemanticNodes.Add(new SemanticNode(
            NodeId:             Guid.NewGuid().ToString("N"),
            Kind:               "ObjectCreationExpression",
            Text:               TruncateText(node.ToString(), 200),
            File:               _filePath,
            Line:               node.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
            Column:             node.GetLocation().GetLineSpan().StartLinePosition.Character + 1,
            ResolvedSymbol:     resolvedSymbol,
            ResolvedType:       resolvedType,
            ContainingMethodId: containingMethodId,
            ContainingClassId:  containingClassId,
            Arguments:          arguments,
            IsAsyncCall:        false,
            IsInTryBlock:       IsInsideTryBlock(node),
            ParentContext:      GetParentContext(node)
        ));

        base.VisitObjectCreationExpression(node);
    }

    // ── Asignaciones ──────────────────────────────────────────────────────────

    public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
    {
        var containingMethodId = FindContainingMethodId(node);
        if (containingMethodId is null) { base.VisitAssignmentExpression(node); return; }

        var targetSymbol = _semanticModel.GetSymbolInfo(node.Left).Symbol;
        var sourceTypeInfo = _semanticModel.GetTypeInfo(node.Right);

        // Determinar el nodo origen (¿viene de una invocación?)
        var sourceNodeId = node.Right is InvocationExpressionSyntax or ObjectCreationExpressionSyntax
            ? FindOrCreateNodeId(node.Right)
            : null;

        var isLiteral = node.Right is LiteralExpressionSyntax;

        Assignments.Add(new AssignmentExport(
            AssignmentId:      Guid.NewGuid().ToString("N"),
            TargetName:        targetSymbol?.Name ?? node.Left.ToString(),
            TargetType:        sourceTypeInfo.Type?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
            SourceNodeId:      sourceNodeId,
            SourceText:        TruncateText(node.Right.ToString(), 100),
            IsLiteral:         isLiteral,
            ContainingMethodId: containingMethodId,
            Line:              node.GetLocation().GetLineSpan().StartLinePosition.Line + 1
        ));

        base.VisitAssignmentExpression(node);
    }

    // ── Declaraciones de variables locales ───────────────────────────────────

    public override void VisitLocalDeclarationStatement(LocalDeclarationStatementSyntax node)
    {
        var containingMethodId = FindContainingMethodId(node);
        if (containingMethodId is null) { base.VisitLocalDeclarationStatement(node); return; }

        foreach (var declarator in node.Declaration.Variables)
        {
            if (declarator.Initializer is null) continue;

            var isLiteral    = declarator.Initializer.Value is LiteralExpressionSyntax;
            var targetSymbol = _semanticModel.GetDeclaredSymbol(declarator);
            var sourceType   = _semanticModel.GetTypeInfo(declarator.Initializer.Value);

            var sourceNodeId = declarator.Initializer.Value
                is InvocationExpressionSyntax or ObjectCreationExpressionSyntax
                ? FindOrCreateNodeId(declarator.Initializer.Value)
                : null;

            Assignments.Add(new AssignmentExport(
                AssignmentId:       Guid.NewGuid().ToString("N"),
                TargetName:         declarator.Identifier.Text,
                TargetType:         (targetSymbol as ILocalSymbol)?.Type
                                        .ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                SourceNodeId:       sourceNodeId,
                SourceText:         TruncateText(declarator.Initializer.Value.ToString(), 100),
                IsLiteral:          isLiteral,
                ContainingMethodId: containingMethodId,
                Line:               node.GetLocation().GetLineSpan().StartLinePosition.Line + 1
            ));
        }

        base.VisitLocalDeclarationStatement(node);
    }

    // ── Return statements ─────────────────────────────────────────────────────

    public override void VisitReturnStatement(ReturnStatementSyntax node)
    {
        var containingMethodId = FindContainingMethodId(node);
        if (containingMethodId is null || node.Expression is null)
        {
            base.VisitReturnStatement(node);
            return;
        }

        var returnedNodeId = node.Expression is InvocationExpressionSyntax
            ? FindOrCreateNodeId(node.Expression)
            : null;

        var returnType = _semanticModel.GetTypeInfo(node.Expression).Type
            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        ReturnFlows.Add(new ReturnFlowExport(
            MethodId:          containingMethodId,
            ReturnedNodeIds:   returnedNodeId is not null ? [returnedNodeId] : [],
            ReturnType:        returnType ?? "unknown",
            MayReturnTainted:  node.Expression is not LiteralExpressionSyntax
        ));

        base.VisitReturnStatement(node);
    }

    // ── Atributos ─────────────────────────────────────────────────────────────

    public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
    {
        var methodSymbol = _semanticModel.GetDeclaredSymbol(node) as IMethodSymbol;
        var methodId     = FindContainingMethodId(node);

        if (methodSymbol is not null && methodId is not null)
        {
            ExtractAndRegisterParameterFlows(methodSymbol, methodId);

            foreach (var attr in methodSymbol.GetAttributes())
            {
                var attrName = attr.AttributeClass?.Name ?? "";
                if (IsRelevantAttribute(attrName))
                {
                    Annotations.Add(new AttributeAnnotation(
                        TargetId:          methodId,
                        TargetKind:        "method",
                        AttributeName:     attrName,
                        ResolvedAttribute: attr.AttributeClass
                            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                        Arguments:         attr.ConstructorArguments
                            .Select(a => a.Value?.ToString() ?? "")
                            .ToList()
                    ));
                }
            }
        }

        base.VisitMethodDeclaration(node);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private List<ArgumentExport> ExtractArguments(
        SeparatedSyntaxList<ArgumentSyntax> arguments,
        string? containingMethodId)
    {
        var result = new List<ArgumentExport>();

        for (int i = 0; i < arguments.Count; i++)
        {
            var arg         = arguments[i];
            var expr        = arg.Expression;
            var typeInfo    = _semanticModel.GetTypeInfo(expr);
            var symbolInfo  = _semanticModel.GetSymbolInfo(expr);

            var isLiteral = expr is LiteralExpressionSyntax
                             or DefaultExpressionSyntax
                             or PredefinedTypeSyntax;

            var (origin, originParamName, originNodeId) = DetermineDataFlowOrigin(
                expr, symbolInfo, containingMethodId);

            result.Add(new ArgumentExport(
                Position:           i,
                Text:               TruncateText(expr.ToString(), 80),
                ResolvedType:       typeInfo.Type?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                IsLiteral:          isLiteral,
                DataFlowOrigin:     origin,
                OriginParameterName: originParamName,
                OriginNodeId:       originNodeId,
                NamedParameter:     arg.NameColon?.Name.Identifier.Text
            ));
        }

        return result;
    }

    private (string Origin, string? ParamName, string? NodeId) DetermineDataFlowOrigin(
        ExpressionSyntax expr,
        SymbolInfo symbolInfo,
        string? containingMethodId)
    {
        if (expr is LiteralExpressionSyntax)
            return ("literal", null, null);

        var symbol = symbolInfo.Symbol;

        if (symbol is IParameterSymbol param)
            return ("parameter", param.Name, null);

        if (symbol is IFieldSymbol or IPropertySymbol)
            return ("field", null, null);

        if (symbol is ILocalSymbol)
            return ("local_variable", null, null);

        if (expr is InvocationExpressionSyntax or ObjectCreationExpressionSyntax)
        {
            var nodeId = FindOrCreateNodeId(expr);
            return ("return_value", null, nodeId);
        }

        return ("unknown", null, null);
    }

    private void ExtractAndRegisterParameterFlows(IMethodSymbol symbol, string methodId)
    {
        foreach (var param in symbol.Parameters)
        {
            ParameterFlows.Add(new ParameterFlowExport(
                MethodId:       methodId,
                ParameterName:  param.Name,
                ParameterType:  param.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                UsedInNodeIds:  [],  // Poblado en post-process por el engine Python con los node_ids
                AssignedToIds:  []
            ));
        }
    }

    private string? FindContainingMethodId(SyntaxNode node)
    {
        var methodNode = node.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (methodNode is null) return null;

        var key = (methodNode.SpanStart, methodNode.Span.End);
        return _methodIdByPosition.TryGetValue(key, out var id) ? id : null;
    }

    private string? FindContainingClassId(SyntaxNode node)
    {
        // Simplificado: se cruza con ClassStructureVisitor en el engine Python
        // usando containing_method_id → método → clase
        return null;
    }

    // Cache para evitar crear múltiples IDs para el mismo nodo de expresión
    private readonly Dictionary<int, string> _nodeIdCache = [];

    private string? FindOrCreateNodeId(ExpressionSyntax expr)
    {
        var key = expr.SpanStart;
        if (_nodeIdCache.TryGetValue(key, out var id)) return id;
        var newId = Guid.NewGuid().ToString("N");
        _nodeIdCache[key] = newId;
        return newId;
    }

    private static bool IsInsideTryBlock(SyntaxNode node) =>
        node.AncestorsAndSelf().Any(n => n is TryStatementSyntax);

    private static List<string> GetParentContext(SyntaxNode node) =>
        node.Ancestors()
            .Take(3)
            .Select(n => n.Kind().ToString())
            .ToList();

    private static bool IsRelevantAttribute(string name) =>
        name is "HttpGetAttribute" or "HttpPostAttribute" or "HttpPutAttribute"
               or "HttpDeleteAttribute" or "HttpPatchAttribute" or "RouteAttribute"
               or "AuthorizeAttribute" or "AllowAnonymousAttribute"
               or "ValidateAntiForgeryTokenAttribute" or "OperationContractAttribute"
               or "WebMethodAttribute";

    private static string TruncateText(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..maxLength] + "…";

    
    // ── Acceso a indexers (Request.Query["id"], Request.Form["x"], etc.) ──────
    public override void VisitElementAccessExpression(ElementAccessExpressionSyntax node)
    {
        var typeInfo   = _semanticModel.GetTypeInfo(node.Expression);
        var symbolInfo = _semanticModel.GetSymbolInfo(node);
        
        // Resolver el tipo del objeto sobre el que se indexa
        var containerType = typeInfo.Type
            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        // Solo registrar si el contenedor es un tipo de source conocido
        // (IQueryCollection, IFormCollection, IHeaderDictionary, etc.)
        var knownSourcePrefixes = new[]
        {
            "Microsoft.AspNetCore.Http.IQueryCollection",
            "Microsoft.AspNetCore.Http.IFormCollection",
            "Microsoft.AspNetCore.Http.IHeaderDictionary",
            "Microsoft.AspNetCore.Http.HttpRequest",
            "System.Web.HttpRequest",
        };

        var containerTypeNormalized = containerType?.Replace("global::", "") ?? "";
        bool isKnownSource = containerTypeNormalized.Length > 0
            && knownSourcePrefixes.Any(p =>
                containerTypeNormalized.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        if (!isKnownSource && !_includeUnresolved)
        {
            base.VisitElementAccessExpression(node);
            return;
        }

        // El símbolo resuelto será el tipo del contenedor + "[indexer]"
        // Ejemplo: "Microsoft.AspNetCore.Http.IQueryCollection[string]"
        var resolvedSymbol = containerType is not null
            ? $"{containerType.Replace("global::", "")}[indexer]"
            : null;

        var returnType = _semanticModel.GetTypeInfo(node).Type
            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        var containingMethodId = FindContainingMethodId(node);
        var containingClassId  = FindContainingClassId(node);

        var arguments = node.ArgumentList.Arguments.Count > 0
            ? ExtractArguments(node.ArgumentList.Arguments, containingMethodId)
            : new List<ArgumentExport>();

        var semanticNode = new SemanticNode(
            NodeId:             Guid.NewGuid().ToString("N"),
            Kind:               "ElementAccessExpression",
            Text:               TruncateText(node.ToString(), 200),
            File:               _filePath,
            Line:               node.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
            Column:             node.GetLocation().GetLineSpan().StartLinePosition.Character + 1,
            ResolvedSymbol:     resolvedSymbol,
            ResolvedType:       returnType,
            ContainingMethodId: containingMethodId,
            ContainingClassId:  containingClassId,
            Arguments:          arguments,
            IsAsyncCall:        false,
            IsInTryBlock:       IsInsideTryBlock(node),
            ParentContext:      GetParentContext(node)
        );

        SemanticNodes.Add(semanticNode);
        base.VisitElementAccessExpression(node);
    }

    // ── Acceso a miembros de sources HTTP (Request.Query, Request.Form, etc.) ──
    public override void VisitMemberAccessExpression(MemberAccessExpressionSyntax node)
    {
        var typeInfo = _semanticModel.GetTypeInfo(node);
        var resolvedType = typeInfo.Type
            ?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        // Registrar solo accesos a propiedades de HttpRequest que son sources
        var knownHttpRequestMembers = new[]
        {
            "Microsoft.AspNetCore.Http.IQueryCollection",
            "Microsoft.AspNetCore.Http.IFormCollection",
            "Microsoft.AspNetCore.Http.IHeaderDictionary",
            "Microsoft.AspNetCore.Http.IFormFileCollection",
            "System.Web.HttpRequestBase",
        };

        var resolvedTypeNormalized = resolvedType?.Replace("global::", "") ?? "";
        bool isSourceType = resolvedTypeNormalized.Length > 0
            && knownHttpRequestMembers.Any(p =>
                resolvedTypeNormalized.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        if (!isSourceType)
        {
            base.VisitMemberAccessExpression(node);
            return;
        }

        var containingMethodId = FindContainingMethodId(node);

        SemanticNodes.Add(new SemanticNode(
            NodeId:             Guid.NewGuid().ToString("N"),
            Kind:               "MemberAccessExpression",
            Text:               TruncateText(node.ToString(), 200),
            File:               _filePath,
            Line:               node.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
            Column:             node.GetLocation().GetLineSpan().StartLinePosition.Character + 1,
            ResolvedSymbol:     resolvedType,
            ResolvedType:       resolvedType,
            ContainingMethodId: containingMethodId,
            ContainingClassId:  FindContainingClassId(node),
            Arguments:          [],
            IsAsyncCall:        false,
            IsInTryBlock:       IsInsideTryBlock(node),
            ParentContext:      GetParentContext(node)
        ));

        base.VisitMemberAccessExpression(node);
    }
}
