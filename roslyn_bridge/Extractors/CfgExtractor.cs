// =============================================================================
//  csharp-sast / roslyn_bridge / Extractors / CfgExtractor.cs
// =============================================================================
//
//  EXTRACTOR DE CONTROL FLOW GRAPH (CFG)
//  ───────────────────────────────────────
//  Extrae el CFG nativo de Roslyn usando la API de FlowAnalysis.
//
//  DIFERENCIA CON UN CFG CONSTRUIDO MANUALMENTE:
//    El CFG de Roslyn (ControlFlowGraph) es el mismo que usa el
//    compilador internamente. Conoce:
//      • Bloques básicos reales (no aproximaciones)
//      • Flujo de excepciones (try/catch/finally)
//      • Branches de switch/pattern matching
//      • Flujo de async/await (continuaciones)
//      • Operadores de cortocircuito (&& ||)
//
//  POR QUÉ ES CRÍTICO PARA SAST:
//    Sin un CFG preciso el taint analyzer no puede determinar
//    si un dato tainted SIEMPRE llega a un sink (vuln definitiva)
//    o PUEDE llegar (vuln potencial). La diferencia determina la
//    severidad y el número de falsos positivos.
//
//  FLUJO DE TRABAJO:
//    1. Para cada método encontrado en el SyntaxTree
//    2. Obtener el ControlFlowGraph via ControlFlowGraph.Create()
//    3. Convertir BasicBlocks → CfgBlockExport
//    4. Extraer ControlFlowBranch → CfgEdgeExport
//    5. Mapear BlockIds → node_ids de SemanticNodes del método
//
// =============================================================================

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using RoslynBridge.Models;

namespace RoslynBridge.Extractors;

/// <summary>
/// Extrae el CFG nativo de Roslyn para cada método del código analizado.
/// Popula el campo ControlFlowExport del RoslynExportRoot.
/// </summary>
public sealed class CfgExtractor
{
    private readonly ILogger<CfgExtractor> _logger;

    public CfgExtractor(ILogger<CfgExtractor> logger)
    {
        _logger = logger;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  MÉTODO PRINCIPAL
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Extrae el CFG de todos los métodos en los SyntaxTrees proporcionados.
    /// Popula el campo ControlFlow del RoslynExportRoot existente.
    /// </summary>
    /// <param name="exportRoot">El export root generado por SemanticExtractor.</param>
    /// <param name="compilation">La compilación en memoria de Roslyn.</param>
    /// <param name="syntaxTrees">Los SyntaxTrees de los archivos analizados.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    public async Task<ControlFlowExport> ExtractAsync(
        RoslynExportRoot exportRoot,
        CSharpCompilation compilation,
        IReadOnlyList<SyntaxTree> syntaxTrees,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Extrayendo CFG de {Count} árbol(es) de sintaxis", syntaxTrees.Count);

        // Construir mapa de method_id → SemanticNodes para poder
        // asignar node_ids a cada bloque del CFG.
        var nodesByMethodId = BuildNodesByMethodId(exportRoot);

        var methodCfgs = new List<MethodCfgExport>();
        int totalMethods = 0, failedMethods = 0;

        foreach (var tree in syntaxTrees)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var semanticModel = compilation.GetSemanticModel(tree);
            var root          = await tree.GetRootAsync(cancellationToken);

            // Procesar todos los métodos del archivo
            foreach (var methodSyntax in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                cancellationToken.ThrowIfCancellationRequested();
                totalMethods++;

                try
                {
                    var methodSymbol = semanticModel.GetDeclaredSymbol(methodSyntax);
                    if (methodSymbol is null) continue;

                    // Obtener el method_id del ExportSchema (generado por SemanticExtractor)
                    var methodExport = FindMethodExport(exportRoot, methodSymbol);
                    if (methodExport is null) continue;

                    // Extraer CFG nativo de Roslyn
                    var cfg = ControlFlowGraph.Create(methodSyntax, semanticModel, cancellationToken);
                    if (cfg is null)
                    {
                        _logger.LogDebug("CFG no disponible para {Method}", methodSymbol.Name);
                        continue;
                    }

                    var nodesForMethod = nodesByMethodId.GetValueOrDefault(methodExport.MethodId, []);
                    var methodCfg      = ConvertToCfgExport(cfg, methodExport, nodesForMethod);
                    methodCfgs.Add(methodCfg);

                    _logger.LogDebug(
                        "CFG extraído: {Method} — {Blocks} bloques, {Edges} aristas",
                        methodSymbol.Name, methodCfg.Blocks.Count, methodCfg.Edges.Count);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failedMethods++;
                    _logger.LogWarning(
                        "No se pudo extraer CFG de método en línea {Line}: {Error}",
                        methodSyntax.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        ex.Message);
                }
            }

            // Procesar también constructores y property accessors
            foreach (var ctorSyntax in root.DescendantNodes().OfType<ConstructorDeclarationSyntax>())
            {
                cancellationToken.ThrowIfCancellationRequested();
                totalMethods++;

                try
                {
                    var semanticModelLocal = compilation.GetSemanticModel(tree);
                    var cfg = ControlFlowGraph.Create(ctorSyntax, semanticModelLocal, cancellationToken);
                    if (cfg is null) continue;

                    var ctorSymbol = semanticModelLocal.GetDeclaredSymbol(ctorSyntax);
                    if (ctorSymbol is null) continue;

                    var methodExport = FindMethodExportByName(exportRoot, ctorSymbol.ContainingType.Name + "..ctor");
                    if (methodExport is null) continue;

                    var nodesForCtor = nodesByMethodId.GetValueOrDefault(methodExport.MethodId, []);
                    methodCfgs.Add(ConvertToCfgExport(cfg, methodExport, nodesForCtor));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failedMethods++;
                    _logger.LogDebug("CFG de constructor fallido: {Error}", ex.Message);
                }
            }
        }

        _logger.LogInformation(
            "CFG completado: {Success}/{Total} métodos exitosos, {Failed} fallidos",
            totalMethods - failedMethods, totalMethods, failedMethods);

        return new ControlFlowExport(Methods: methodCfgs);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  CONVERSIÓN DE CFG NATIVO → EXPORT SCHEMA
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Convierte el ControlFlowGraph nativo de Roslyn al formato ExportSchema.
    /// </summary>
    private MethodCfgExport ConvertToCfgExport(
        ControlFlowGraph cfg,
        MethodExport methodExport,
        List<SemanticNode> nodesInMethod)
    {
        // Mapa de BasicBlock.Ordinal → CfgBlockExport.BlockId
        // Necesario para construir las aristas correctamente.
        var blockIdByOrdinal = new Dictionary<int, string>();

        // ── 1. Convertir bloques básicos ──────────────────────────────────────
        var blocks      = new List<CfgBlockExport>();
        var edges       = new List<CfgEdgeExport>();

        foreach (var basicBlock in cfg.Blocks)
        {
            var blockId = Guid.NewGuid().ToString("N");
            blockIdByOrdinal[basicBlock.Ordinal] = blockId;

            var blockKind = DetermineBlockKind(basicBlock);

            // Determinar rango de líneas del bloque
            var (lineStart, lineEnd) = GetBlockLineRange(basicBlock);

            // Encontrar los SemanticNodes que ocurren dentro de este bloque
            // (intersección de rangos de línea)
            var nodeIds = nodesInMethod
                .Where(n => n.Line >= lineStart && n.Line <= lineEnd)
                .Select(n => n.NodeId)
                .ToList();

            // Extraer condición de rama si aplica
            string? branchCondition = null;
            if (basicBlock.BranchValue?.Syntax is not null)
                branchCondition = TruncateText(basicBlock.BranchValue.Syntax.ToString(), 100);

            blocks.Add(new CfgBlockExport(
                BlockId:              blockId,
                Kind:                 blockKind,
                NodeIds:              nodeIds,
                LineStart:            lineStart,
                LineEnd:              lineEnd,
                BranchCondition:      branchCondition,
                IsExceptionHandler:   basicBlock.IsReachable && basicBlock.Kind == BasicBlockKind.Block
                                      && IsExceptionHandlerBlock(basicBlock, cfg)
            ));
        }

        // ── 2. Construir aristas del CFG ──────────────────────────────────────
        foreach (var basicBlock in cfg.Blocks)
        {
            var fromId = blockIdByOrdinal[basicBlock.Ordinal];

            // Rama condicional true (fallthrough)
            if (basicBlock.FallThroughSuccessor is not null
                && basicBlock.FallThroughSuccessor.Destination is not null)
            {
                var toBlock = basicBlock.FallThroughSuccessor.Destination;
                if (blockIdByOrdinal.TryGetValue(toBlock.Ordinal, out var toId))
                {
                    var edgeKind = DetermineEdgeKind(
                        basicBlock.FallThroughSuccessor,
                        basicBlock,
                        isFallthrough: true);

                    edges.Add(new CfgEdgeExport(
                        FromBlockId: fromId,
                        ToBlockId:   toId,
                        EdgeKind:    edgeKind
                    ));
                }
            }

            // Rama condicional false (conditional successor)
            if (basicBlock.ConditionalSuccessor is not null
                && basicBlock.ConditionalSuccessor.Destination is not null)
            {
                var toBlock = basicBlock.ConditionalSuccessor.Destination;
                if (blockIdByOrdinal.TryGetValue(toBlock.Ordinal, out var toId))
                {
                    var edgeKind = DetermineEdgeKind(
                        basicBlock.ConditionalSuccessor,
                        basicBlock,
                        isFallthrough: false);

                    edges.Add(new CfgEdgeExport(
                        FromBlockId: fromId,
                        ToBlockId:   toId,
                        EdgeKind:    edgeKind
                    ));
                }
            }
        }

        // ── 3. Identificar bloques de entrada y salida ────────────────────────
        var entryBlockId = blockIdByOrdinal.TryGetValue(cfg.Blocks[0].Ordinal, out var eid)
            ? eid : blockIdByOrdinal.Values.First();

        var exitBlockIds = cfg.Blocks
            .Where(b => b.Kind == BasicBlockKind.Exit)
            .Where(b => blockIdByOrdinal.ContainsKey(b.Ordinal))
            .Select(b => blockIdByOrdinal[b.Ordinal])
            .ToList();

        return new MethodCfgExport(
            MethodId:     methodExport.MethodId,
            MethodName:   methodExport.Name,
            Blocks:       blocks,
            Edges:        edges,
            EntryBlockId: entryBlockId,
            ExitBlockIds: exitBlockIds
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private static string DetermineBlockKind(BasicBlock block) =>
        block.Kind switch
        {
            BasicBlockKind.Entry => "entry",
            BasicBlockKind.Exit  => "exit",
            _                    => "basic"
        };

    private static string DetermineEdgeKind(
    ControlFlowBranch branch,
    BasicBlock fromBlock,
    bool isFallthrough)
    {
        // Regular sin condición = sequential (fallthrough incondicional)
        if (branch.Semantics == ControlFlowBranchSemantics.Regular &&
            fromBlock.BranchValue is null)
            return "sequential";

        if (branch.Semantics == ControlFlowBranchSemantics.Return)
            return "return";

        // Throw y Rethrow — usar || en lugar de 'or' para compatibilidad
        if (branch.Semantics == ControlFlowBranchSemantics.Throw
            || branch.Semantics == ControlFlowBranchSemantics.Rethrow)
            return "throw";

        if (branch.Semantics == ControlFlowBranchSemantics.Error)
            return "exception";

        // Branches condicionales (if/while/switch)
        if (fromBlock.BranchValue is not null)
            return isFallthrough ? "true_branch" : "false_branch";

        return "sequential";
    }

    private static (int LineStart, int LineEnd) GetBlockLineRange(BasicBlock block)
    {
        if (!block.Operations.Any())
            return (0, 0);

        int minLine = int.MaxValue, maxLine = 0;

        foreach (var op in block.Operations)
        {
            if (op.Syntax is null) continue;
            var span = op.Syntax.GetLocation().GetLineSpan();
            var start = span.StartLinePosition.Line + 1;
            var end   = span.EndLinePosition.Line   + 1;

            if (start < minLine) minLine = start;
            if (end   > maxLine) maxLine = end;
        }

        // También considerar el BranchValue
        if (block.BranchValue?.Syntax is not null)
        {
            var span  = block.BranchValue.Syntax.GetLocation().GetLineSpan();
            var start = span.StartLinePosition.Line + 1;
            var end   = span.EndLinePosition.Line   + 1;
            if (start < minLine) minLine = start;
            if (end   > maxLine) maxLine = end;
        }

        return minLine == int.MaxValue ? (0, 0) : (minLine, maxLine);
    }

    private static bool IsExceptionHandlerBlock(BasicBlock block, ControlFlowGraph cfg)
    {
        return IsBlockInExceptionRegion(block.Ordinal, cfg.Root);
    }

    private static bool IsBlockInExceptionRegion(int blockOrdinal, ControlFlowRegion region)
    {
        // Verificar si el bloque está dentro de esta región y la región es Catch/Finally
        bool inRange = region.FirstBlockOrdinal <= blockOrdinal
                    && region.LastBlockOrdinal  >= blockOrdinal;

        if (inRange && region.Kind is ControlFlowRegionKind.Catch
                                or ControlFlowRegionKind.Finally)
            return true;

        // Recorrer las sub-regiones recursivamente
        if (inRange)
        {
            foreach (var nested in region.NestedRegions)
            {
                if (IsBlockInExceptionRegion(blockOrdinal, nested))
                    return true;
            }
        }

        return false;
    }

    private static Dictionary<string, List<SemanticNode>> BuildNodesByMethodId(RoslynExportRoot root)
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

    private static MethodExport? FindMethodExport(RoslynExportRoot root, IMethodSymbol symbol)
    {
        var fullName = symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        return root.CompilationUnit.Classes
            .SelectMany(c => c.Methods)
            .FirstOrDefault(m =>
                m.Signature.Contains(symbol.Name, StringComparison.OrdinalIgnoreCase));
    }

    private static MethodExport? FindMethodExportByName(RoslynExportRoot root, string nameFragment) =>
        root.CompilationUnit.Classes
            .SelectMany(c => c.Methods)
            .FirstOrDefault(m => m.Name.Contains(nameFragment, StringComparison.OrdinalIgnoreCase));

    private static string TruncateText(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..maxLength] + "…";
}