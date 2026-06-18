// =============================================================================
//  csharp-sast / roslyn_bridge / Extractors / DfgExtractor.cs
// =============================================================================
//
//  EXTRACTOR DE DATA FLOW GRAPH (DFG)
//  ────────────────────────────────────
//  Enriquece el DataFlowExport generado por SemanticExtractor con:
//
//    1. Análisis de DataFlow nativo de Roslyn (definite assignment,
//       always-assigned, read-inside, written-inside)
//    2. Propagación de taint inter-procedural (entre métodos)
//    3. Rastreo de aliases (var x = input; → SqlCommand(x))
//    4. Rastreo de flujo a través de async/await
//    5. Flujo a través de colecciones (List<T>, Dictionary<K,V>)
//    6. Marcado de ParameterFlows con los node_ids donde se usa cada parámetro
//
//  POR QUÉ ROSLYN DataFlowAnalysis:
//    Roslyn.DataFlowAnalysis.AnalyzeDataFlow() es el análisis de flujo de
//    datos del compilador real. Determina con precisión:
//      • AlwaysAssigned: variables siempre inicializadas antes de uso
//      • ReadInside/WrittenInside: qué se lee/escribe en un bloque
//      • DataFlowsIn/DataFlowsOut: qué datos entran/salen
//      • Captured: variables capturadas por lambdas (closures)
//
//  RELACIÓN CON EL ENGINE PYTHON:
//    El DFG exportado aquí es consumido por dfg_builder.py que construye
//    el grafo NetworkX y ejecuta el taint propagation algorithm.
//    DfgExtractor no ejecuta taint analysis — eso es responsabilidad del engine.
//
// =============================================================================

using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RoslynBridge.Models;

namespace RoslynBridge.Extractors;

/// <summary>
/// Enriquece el DataFlowExport usando el análisis de flujo de datos nativo de Roslyn.
/// Se ejecuta después de SemanticExtractor y CfgExtractor.
/// </summary>
public sealed class DfgExtractor
{
    private readonly ILogger<DfgExtractor> _logger;
    private readonly SymbolResolver _symbolResolver;

    public DfgExtractor(ILogger<DfgExtractor> logger, SymbolResolver symbolResolver)
    {
        _logger         = logger;
        _symbolResolver = symbolResolver;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  MÉTODO PRINCIPAL
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Enriquece el DataFlowExport del RoslynExportRoot con información
    /// de flujo de datos de Roslyn y análisis de alias.
    /// </summary>
    public async Task<DataFlowExport> EnrichAsync(
        RoslynExportRoot exportRoot,
        CSharpCompilation compilation,
        IReadOnlyList<SyntaxTree> syntaxTrees,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Iniciando enriquecimiento del DFG con Roslyn DataFlowAnalysis");

        var enrichedAssignments  = new ConcurrentBag<AssignmentExport>(exportRoot.DataFlow.Assignments);
        var enrichedParamFlows   = new List<ParameterFlowExport>(exportRoot.DataFlow.ParameterFlows);
        var enrichedReturnFlows  = new List<ReturnFlowExport>(exportRoot.DataFlow.ReturnFlows);

        // Mapa rápido: methodId → SemanticNodes del método
        var nodesByMethod = BuildNodesByMethod(exportRoot);

        // Mapa rápido: methodId → MethodExport
        var methodById = BuildMethodMap(exportRoot);

        var semaphore = new SemaphoreSlim(Environment.ProcessorCount);

        var tasks = syntaxTrees.Select(async tree =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                var semanticModel = compilation.GetSemanticModel(tree);
                var root          = await tree.GetRootAsync(cancellationToken);

                foreach (var methodSyntax in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var methodSymbol = semanticModel.GetDeclaredSymbol(methodSyntax);
                    if (methodSymbol is null) continue;

                    var methodExport = FindMethodExport(exportRoot, methodSymbol);
                    if (methodExport is null) continue;

                    var nodesInMethod = nodesByMethod.GetValueOrDefault(methodExport.MethodId, []);

                    // ── A. Análisis de DataFlow nativo de Roslyn ──────────────
                    EnrichWithRoslynDataFlow(
                        methodSyntax, semanticModel, methodExport,
                        nodesInMethod, enrichedAssignments);

                    // ── B. Rastreo de aliases ─────────────────────────────────
                    var aliases = ExtractAliases(methodSyntax, semanticModel, methodExport.MethodId);

                    // ── C. Enriquecer ParameterFlows con node_ids de uso ──────
                    EnrichParameterFlows(
                        methodSyntax, semanticModel, methodExport,
                        nodesInMethod, aliases, enrichedParamFlows);

                    // ── D. Análisis de captura de closures/lambdas ───────────
                    EnrichLambdaCaptures(
                        methodSyntax, semanticModel, methodExport,
                        nodesInMethod, enrichedAssignments);

                    // ── E. Flujo a través de colecciones ─────────────────────
                    EnrichCollectionFlows(
                        methodSyntax, semanticModel, methodExport,
                        nodesInMethod, enrichedAssignments);
                }
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);

        // ── F. Análisis inter-procedural ──────────────────────────────────────
        var interProcFlows = AnalyzeInterProceduralFlows(exportRoot, nodesByMethod, methodById);
        foreach (var flow in interProcFlows)
            enrichedAssignments.Add(flow);

        // ── G. Marcar ReturnFlows con mayReturnTainted ────────────────────────
        var finalReturnFlows = EnrichReturnFlows(enrichedReturnFlows, exportRoot);

        _logger.LogInformation(
            "DFG enriquecido: {Assignments} asignaciones, {ParamFlows} flujos de parámetro, {ReturnFlows} flujos de retorno",
            enrichedAssignments.Count, enrichedParamFlows.Count, finalReturnFlows.Count);

        return new DataFlowExport(
            Assignments:    enrichedAssignments.ToList(),
            ParameterFlows: enrichedParamFlows,
            ReturnFlows:    finalReturnFlows
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  A. ENRIQUECIMIENTO CON ROSLYN DataFlowAnalysis
    // ─────────────────────────────────────────────────────────────────────────

    private void EnrichWithRoslynDataFlow(
        MethodDeclarationSyntax methodSyntax,
        SemanticModel semanticModel,
        MethodExport methodExport,
        List<SemanticNode> nodesInMethod,
        ConcurrentBag<AssignmentExport> assignments)
    {
        if (methodSyntax.Body is null && methodSyntax.ExpressionBody is null) return;

        try
        {
            // Analizar el flujo de datos de todo el cuerpo del método
            SyntaxNode bodyToAnalyze = methodSyntax.Body is not null
                ? (SyntaxNode)methodSyntax.Body
                : methodSyntax.ExpressionBody!;

            var dataFlow = semanticModel.AnalyzeDataFlow(bodyToAnalyze);
            if (dataFlow is null || !dataFlow.Succeeded) return;

            // Variables capturadas por referencia en closures → pueden ser tainted
            foreach (var capturedVar in dataFlow.Captured)
            {
                if (capturedVar is not ILocalSymbol localVar) continue;

                var capturedType = localVar.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

                // Encontrar el nodo donde se captura la variable
                var capturingNodes = nodesInMethod
                    .Where(n => n.Arguments.Any(a =>
                        a.DataFlowOrigin == "local_variable"
                        && a.Text.Contains(localVar.Name, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                if (capturingNodes.Count == 0) continue;

                assignments.Add(new AssignmentExport(
                    AssignmentId:       Guid.NewGuid().ToString("N"),
                    TargetName:         $"__captured_{localVar.Name}",
                    TargetType:         capturedType,
                    SourceNodeId:       capturingNodes.First().NodeId,
                    SourceText:         localVar.Name,
                    IsLiteral:          false,
                    ContainingMethodId: methodExport.MethodId,
                    Line:               0  // Línea de captura no disponible directamente
                ));
            }

            // Verificar variables que fluyen hacia el exterior del método
            // (WrittenOutside) — útil para detectar side effects tainted
            foreach (var writtenOutside in dataFlow.WrittenOutside)
            {
                _logger.LogDebug(
                    "Variable escrita fuera del método {Method}: {Var}",
                    methodExport.Name, writtenOutside.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(
                "DataFlowAnalysis falló para {Method}: {Error}",
                methodExport.Name, ex.Message);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  B. RASTREO DE ALIASES
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Extrae el mapa de aliases dentro de un método.
    /// Un alias es cuando una variable local recibe el valor de un parámetro:
    ///   var query = userId;         // query es alias de userId
    ///   var cmd = new SqlCommand(query);  // → tainted si userId es tainted
    ///
    /// El engine Python usa estos aliases para la propagación de taint.
    /// </summary>
    private Dictionary<string, string> ExtractAliases(
        MethodDeclarationSyntax methodSyntax,
        SemanticModel semanticModel,
        string methodId)
    {
        var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var localDecl in methodSyntax.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
        {
            foreach (var declarator in localDecl.Declaration.Variables)
            {
                if (declarator.Initializer is null) continue;

                var initExpr   = declarator.Initializer.Value;
                var initSymbol = semanticModel.GetSymbolInfo(initExpr).Symbol;

                // Si la inicialización es directamente un parámetro o una variable local
                if (initSymbol is IParameterSymbol param)
                {
                    aliases[declarator.Identifier.Text] = param.Name;
                    _logger.LogDebug(
                        "Alias detectado en {Method}: {Var} → param:{Param}",
                        methodId, declarator.Identifier.Text, param.Name);
                }
                else if (initSymbol is ILocalSymbol local && aliases.ContainsKey(local.Name))
                {
                    // Alias transitivo: var c = b; donde b ya es alias de a
                    aliases[declarator.Identifier.Text] = aliases[local.Name];
                }
            }
        }

        return aliases;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  C. ENRIQUECIMIENTO DE PARAMETER FLOWS
    // ─────────────────────────────────────────────────────────────────────────

    private void EnrichParameterFlows(
        MethodDeclarationSyntax methodSyntax,
        SemanticModel semanticModel,
        MethodExport methodExport,
        List<SemanticNode> nodesInMethod,
        Dictionary<string, string> aliases,
        List<ParameterFlowExport> paramFlows)
    {
        var paramNames = methodExport.Parameters.Select(p => p.Name).ToHashSet();

        // Para cada parámetro, encontrar los nodos donde se usa
        foreach (var param in methodExport.Parameters)
        {
            // Encontrar nodos donde el parámetro (o sus aliases) aparece como argumento
            var usedInNodeIds = nodesInMethod
                .Where(n => n.Arguments.Any(a =>
                    (a.DataFlowOrigin == "parameter" && a.OriginParameterName == param.Name)
                    || (a.DataFlowOrigin == "local_variable"
                        && aliases.TryGetValue(a.Text, out var aliasOrigin)
                        && aliasOrigin == param.Name)))
                .Select(n => n.NodeId)
                .Distinct()
                .ToList();

            // Encontrar asignaciones donde el parámetro se asigna a variables locales
            var assignedToIds = nodesInMethod
                .Where(n => n.Kind == "LocalDeclaration"
                    && n.Arguments.Any(a => a.OriginParameterName == param.Name))
                .Select(n => n.NodeId)
                .ToList();

            // También considerar aliases: var x = param → agregar el nodo de x
            var aliasAssignedTo = aliases
                .Where(kv => kv.Value == param.Name)
                .Select(kv => kv.Key)
                .ToList();

            if (usedInNodeIds.Count == 0 && assignedToIds.Count == 0) continue;

            // Reemplazar el ParameterFlow existente (generado por SemanticExtractor)
            // con la versión enriquecida
            lock (paramFlows)
            {
                var existingIdx = paramFlows.FindIndex(
                    pf => pf.MethodId == methodExport.MethodId
                       && pf.ParameterName == param.Name);

                var enriched = new ParameterFlowExport(
                    MethodId:       methodExport.MethodId,
                    ParameterName:  param.Name,
                    ParameterType:  param.ResolvedType,
                    UsedInNodeIds:  usedInNodeIds,
                    AssignedToIds:  assignedToIds
                );

                if (existingIdx >= 0)
                    paramFlows[existingIdx] = enriched;
                else
                    paramFlows.Add(enriched);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  D. CAPTURA DE CLOSURES Y LAMBDAS
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Detecta variables capturadas por lambdas y closures.
    /// Importante para async/await donde el método continúa en otro thread:
    ///   var userId = Request.Query["id"];
    ///   var result = await Task.Run(() => SqlQuery(userId));  // userId capturado
    /// </summary>
    private void EnrichLambdaCaptures(
        MethodDeclarationSyntax methodSyntax,
        SemanticModel semanticModel,
        MethodExport methodExport,
        List<SemanticNode> nodesInMethod,
        ConcurrentBag<AssignmentExport> assignments)
    {
        var lambdas = methodSyntax.DescendantNodes()
            .Where(n => n is LambdaExpressionSyntax or AnonymousMethodExpressionSyntax);

        foreach (var lambda in lambdas)
        {
            try
            {
                // Analizar el flujo de datos dentro de la lambda
                var lambdaFlow = semanticModel.AnalyzeDataFlow(lambda);
                if (lambdaFlow is null || !lambdaFlow.Succeeded) continue;

                // Variables capturadas (definidas fuera de la lambda, usadas dentro)
                foreach (var capturedSymbol in lambdaFlow.DataFlowsIn)
                {
                    if (capturedSymbol is not ILocalSymbol and not IParameterSymbol) continue;

                    var capturedName = capturedSymbol.Name;
                    var capturedType = capturedSymbol is ILocalSymbol ls
                        ? ls.Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)
                        : (capturedSymbol as IParameterSymbol)!.Type
                            .ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

                    // Encontrar nodos dentro de la lambda que usan esta variable
                    var loc       = lambda.GetLocation().GetLineSpan();
                    var lambdaStart = loc.StartLinePosition.Line + 1;
                    var lambdaEnd   = loc.EndLinePosition.Line   + 1;

                    var lambdaNodes = nodesInMethod
                        .Where(n => n.Line >= lambdaStart && n.Line <= lambdaEnd
                            && n.Arguments.Any(a => a.Text.Contains(capturedName)))
                        .Select(n => n.NodeId)
                        .FirstOrDefault();

                    if (lambdaNodes is null) continue;

                    assignments.Add(new AssignmentExport(
                        AssignmentId:       Guid.NewGuid().ToString("N"),
                        TargetName:         $"__lambda_capture_{capturedName}",
                        TargetType:         capturedType,
                        SourceNodeId:       lambdaNodes,
                        SourceText:         capturedName,
                        IsLiteral:          false,
                        ContainingMethodId: methodExport.MethodId,
                        Line:               lambdaStart
                    ));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Lambda capture analysis falló: {Error}", ex.Message);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  E. FLUJO A TRAVÉS DE COLECCIONES
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Detecta flujo de taint a través de colecciones:
    ///   list.Add(userInput);         // list contiene datos tainted
    ///   SqlCommand(list[0]);         // → potencial SQL injection
    ///
    /// También detecta flujo a través de LINQ:
    ///   var queries = items.Select(i => $"SELECT * WHERE id={i.Id}");
    /// </summary>
    private void EnrichCollectionFlows(
        MethodDeclarationSyntax methodSyntax,
        SemanticModel semanticModel,
        MethodExport methodExport,
        List<SemanticNode> nodesInMethod,
        ConcurrentBag<AssignmentExport> assignments)
    {
        // Detectar invocaciones de Add/AddRange/Append a colecciones
        var collectionAdds = methodSyntax.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv =>
            {
                var name = inv.Expression is MemberAccessExpressionSyntax ma
                    ? ma.Name.Identifier.Text : null;
                return name is "Add" or "AddRange" or "Append" or "Push" or "Enqueue" or "Insert";
            });

        foreach (var addCall in collectionAdds)
        {
            var symbolInfo     = semanticModel.GetSymbolInfo(addCall);
            var methodSymbol   = symbolInfo.Symbol as IMethodSymbol;
            if (methodSymbol is null) continue;

            // Verificar si el tipo contenedor es una colección genérica
            var containingType = methodSymbol.ContainingType;
            if (!IsGenericCollection(containingType)) continue;

            // Extraer el argumento que se añade a la colección
            var args = addCall.ArgumentList.Arguments;
            if (args.Count == 0) continue;

            var arg        = args[0];
            var argSymbol  = semanticModel.GetSymbolInfo(arg.Expression).Symbol;

            // Si el argumento viene de un parámetro, marcar la colección como tainted
            if (argSymbol is IParameterSymbol paramSym)
            {
                var collectionExpr = addCall.Expression is MemberAccessExpressionSyntax ma2
                    ? ma2.Expression : null;
                var collectionName = collectionExpr?.ToString() ?? "unknown_collection";

                var addLine = addCall.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                assignments.Add(new AssignmentExport(
                    AssignmentId:       Guid.NewGuid().ToString("N"),
                    TargetName:         $"__collection_{collectionName}",
                    TargetType:         containingType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                    SourceNodeId:       null,
                    SourceText:         $"{collectionName}.Add({paramSym.Name})",
                    IsLiteral:          false,
                    ContainingMethodId: methodExport.MethodId,
                    Line:               addLine
                ));
            }
        }

        // Detectar string concatenación y interpolación tainted
        EnrichStringInterpolationFlows(methodSyntax, semanticModel, methodExport, assignments);
    }

    private void EnrichStringInterpolationFlows(
        MethodDeclarationSyntax methodSyntax,
        SemanticModel semanticModel,
        MethodExport methodExport,
        ConcurrentBag<AssignmentExport> assignments)
    {
        // Interpolated strings: $"SELECT * WHERE id = {userId}" → sink riesgo
        var interpolations = methodSyntax.DescendantNodes()
            .OfType<InterpolatedStringExpressionSyntax>();

        foreach (var interp in interpolations)
        {
            if (!SymbolResolver.IsInterpolatedStringWithExternalData(interp, semanticModel))
                continue;

            var loc  = interp.GetLocation().GetLineSpan();
            var line = loc.StartLinePosition.Line + 1;

            assignments.Add(new AssignmentExport(
                AssignmentId:       Guid.NewGuid().ToString("N"),
                TargetName:         "__interpolated_string",
                TargetType:         "System.String",
                SourceNodeId:       null,
                SourceText:         TruncateText(interp.ToString(), 120),
                IsLiteral:          false,
                ContainingMethodId: methodExport.MethodId,
                Line:               line
            ));
        }

        // String concatenation: "SELECT * WHERE id=" + userId → sink riesgo
        var binaryAdds = methodSyntax.DescendantNodes()
            .OfType<BinaryExpressionSyntax>()
            .Where(b => b.OperatorToken.IsKind(SyntaxKind.PlusToken));

        foreach (var concat in binaryAdds)
        {
            var rightSymbol = semanticModel.GetSymbolInfo(concat.Right).Symbol;
            if (rightSymbol is not IParameterSymbol and not ILocalSymbol) continue;

            var leftType = semanticModel.GetTypeInfo(concat.Left).Type?.SpecialType;
            if (leftType != SpecialType.System_String) continue;

            var loc  = concat.GetLocation().GetLineSpan();
            var line = loc.StartLinePosition.Line + 1;

            assignments.Add(new AssignmentExport(
                AssignmentId:       Guid.NewGuid().ToString("N"),
                TargetName:         "__string_concat",
                TargetType:         "System.String",
                SourceNodeId:       null,
                SourceText:         TruncateText(concat.ToString(), 120),
                IsLiteral:          false,
                ContainingMethodId: methodExport.MethodId,
                Line:               line
            ));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  F. ANÁLISIS INTER-PROCEDURAL
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Detecta flujos de datos entre métodos (inter-procedural analysis).
    ///
    /// Escenario:
    ///   string GetUserInput() { return Request.Query["id"]; }    // source
    ///   void SaveUser() { var id = GetUserInput(); SqlCmd(id); } // sink via call
    ///
    /// El bridge detecta que GetUserInput() retorna datos potencialmente tainted
    /// y lo registra como un AssignmentExport con IsLiteral=false.
    /// El engine Python completa el análisis con el taint_analyzer.
    /// </summary>
    private List<AssignmentExport> AnalyzeInterProceduralFlows(
        RoslynExportRoot exportRoot,
        Dictionary<string, List<SemanticNode>> nodesByMethod,
        Dictionary<string, MethodExport> methodById)
    {
        var interProcFlows = new List<AssignmentExport>();

        // Construir mapa: methodName → ReturnFlowExport
        var returnFlowByMethod = exportRoot.DataFlow.ReturnFlows
            .GroupBy(r => r.MethodId)
            .ToDictionary(g => g.Key, g => g.First());

        // Para cada método que llama a otro, verificar si el retorno está tainted
        foreach (var (methodId, nodes) in nodesByMethod)
        {
            foreach (var node in nodes)
            {
                if (node.Kind != "InvocationExpression") continue;
                if (node.ResolvedSymbol is null) continue;

                // Buscar el método llamado en el proyecto (llamada intra-proyecto)
                var calledMethod = FindMethodBySymbol(exportRoot, node.ResolvedSymbol);
                if (calledMethod is null) continue;

                // Verificar si el método llamado tiene un ReturnFlow tainted
                if (!returnFlowByMethod.TryGetValue(calledMethod.MethodId, out var returnFlow))
                    continue;

                if (!returnFlow.MayReturnTainted) continue;

                // Registrar que esta invocación puede retornar datos tainted
                interProcFlows.Add(new AssignmentExport(
                    AssignmentId:       Guid.NewGuid().ToString("N"),
                    TargetName:         $"__interprocedural_{node.NodeId[..8]}",
                    TargetType:         returnFlow.ReturnType,
                    SourceNodeId:       node.NodeId,
                    SourceText:         $"call to {calledMethod.Name}() [may return tainted]",
                    IsLiteral:          false,
                    ContainingMethodId: methodId,
                    Line:               node.Line
                ));
            }
        }

        _logger.LogDebug("Flujos inter-procedurales detectados: {Count}", interProcFlows.Count);
        return interProcFlows;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  G. ENRICHMENT DE RETURN FLOWS
    // ─────────────────────────────────────────────────────────────────────────

    private List<ReturnFlowExport> EnrichReturnFlows(
        List<ReturnFlowExport> returnFlows,
        RoslynExportRoot exportRoot)
    {
        var nodeById = exportRoot.SemanticNodes.ToDictionary(n => n.NodeId);

        return returnFlows.Select(rf =>
        {
            // Verificar si alguno de los nodos retornados es tainted
            var mayBeTainted = rf.MayReturnTainted
                || rf.ReturnedNodeIds.Any(nid =>
                    nodeById.TryGetValue(nid, out var node)
                    && node.HasPotentiallyTaintedArguments());

            return rf with { MayReturnTainted = mayBeTainted };
        }).ToList();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private static Dictionary<string, List<SemanticNode>> BuildNodesByMethod(RoslynExportRoot root)
    {
        var result = new Dictionary<string, List<SemanticNode>>();
        foreach (var node in root.SemanticNodes)
        {
            if (node.ContainingMethodId is null) continue;
            if (!result.TryGetValue(node.ContainingMethodId, out var list))
            {
                list = [];
                result[node.ContainingMethodId] = list;
            }
            list.Add(node);
        }
        return result;
    }

    private static Dictionary<string, MethodExport> BuildMethodMap(RoslynExportRoot root) =>
        root.CompilationUnit.Classes
            .SelectMany(c => c.Methods)
            .ToDictionary(m => m.MethodId);

    private static MethodExport? FindMethodExport(RoslynExportRoot root, IMethodSymbol symbol) =>
        root.CompilationUnit.Classes
            .SelectMany(c => c.Methods)
            .FirstOrDefault(m =>
                m.Signature.Contains(symbol.Name, StringComparison.OrdinalIgnoreCase));

    private static MethodExport? FindMethodBySymbol(RoslynExportRoot root, string resolvedSymbol) =>
        root.CompilationUnit.Classes
            .SelectMany(c => c.Methods)
            .FirstOrDefault(m =>
                resolvedSymbol.Contains(m.Name, StringComparison.OrdinalIgnoreCase));

    private static bool IsGenericCollection(INamedTypeSymbol type)
    {
        var name = type.OriginalDefinition.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return name is
            "global::System.Collections.Generic.List<T>" or
            "global::System.Collections.Generic.IList<T>" or
            "global::System.Collections.Generic.Queue<T>" or
            "global::System.Collections.Generic.Stack<T>" or
            "global::System.Collections.Generic.HashSet<T>" or
            "global::System.Collections.Generic.Dictionary<TKey, TValue>" or
            "global::System.Collections.Generic.IEnumerable<T>";
    }

    private static string TruncateText(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..maxLength] + "…";
}