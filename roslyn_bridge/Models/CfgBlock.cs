// =============================================================================
//  csharp-sast / roslyn_bridge / Models / CfgBlock.cs
//  CORRECCIÓN: Error CS1739 — CfgNode constructor con parámetros posicionales
// =============================================================================

using RoslynBridge.Models;

namespace RoslynBridge.Models;

// ─────────────────────────────────────────────────────────────────────────────
//  GRAFO CFG INTERNO (MUTABLE — SOLO USO DEL BRIDGE)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Representación interna mutable del CFG de un método.
/// Se construye durante la extracción y luego se convierte a MethodCfgExport.
/// No se serializa directamente a JSON.
/// </summary>
public sealed class CfgGraph
{
    private readonly Dictionary<string, CfgNode> _nodes = [];
    private readonly List<CfgEdge> _edges              = [];

    public string MethodId     { get; }
    public string MethodName   { get; }
    public string? EntryNodeId { get; private set; }
    public IReadOnlyList<string> ExitNodeIds => _exitNodeIds;
    private readonly List<string> _exitNodeIds = [];

    public IReadOnlyDictionary<string, CfgNode> Nodes => _nodes;
    public IReadOnlyList<CfgEdge> Edges => _edges;

    public CfgGraph(string methodId, string methodName)
    {
        MethodId   = methodId;
        MethodName = methodName;
    }

    // ── Construcción del grafo ────────────────────────────────────────────────

    public CfgNode AddNode(
        string blockId,
        CfgBlockKind kind,
        int lineStart,
        int lineEnd,
        IReadOnlyList<string> nodeIds,
        string? branchCondition = null,
        bool isExceptionHandler = false)
    {
        // ─────────────────────────────────────────────────────────────────────
        // FIX Error CS1739:
        // CfgNode es una sealed class con constructor que recibe parámetros
        // posicionales. Los named parameters de record no aplican aquí.
        // Se pasan los argumentos en el orden correcto del constructor.
        // ─────────────────────────────────────────────────────────────────────
        var node = new CfgNode(
            blockId,
            kind,
            lineStart,
            lineEnd,
            nodeIds,
            branchCondition,
            isExceptionHandler
        );

        _nodes[blockId] = node;

        if (kind == CfgBlockKind.Entry)
            EntryNodeId = blockId;

        if (kind == CfgBlockKind.Exit)
            _exitNodeIds.Add(blockId);

        return node;
    }

    public void AddEdge(string fromId, string toId, CfgEdgeKind kind)
    {
        if (!_nodes.ContainsKey(fromId) || !_nodes.ContainsKey(toId))
            return;

        var edge = new CfgEdge(fromId, toId, kind);
        _edges.Add(edge);

        _nodes[fromId].AddSuccessor(toId, kind);
        _nodes[toId].AddPredecessor(fromId);
    }

    // ── Algoritmos de análisis de grafo ───────────────────────────────────────

    /// <summary>
    /// Recorrido DFS desde el nodo de entrada.
    /// Retorna los bloques en orden de visita (pre-order).
    /// Usado por el DfgExtractor para propagar taint en orden topológico.
    /// </summary>
    public IEnumerable<CfgNode> DepthFirstSearch()
    {
        if (EntryNodeId is null || !_nodes.ContainsKey(EntryNodeId))
            yield break;

        var visited = new HashSet<string>();
        var stack   = new Stack<string>();
        stack.Push(EntryNodeId);

        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if (!visited.Add(current)) continue;

            if (!_nodes.TryGetValue(current, out var node)) continue;
            yield return node;

            // Visitar sucesores en orden inverso para mantener orden lógico
            foreach (var successorId in node.Successors.Keys.Reverse())
                if (!visited.Contains(successorId))
                    stack.Push(successorId);
        }
    }

    /// <summary>
    /// Recorrido BFS desde el nodo de entrada.
    /// Retorna los bloques en orden de anchura (útil para análisis de dominancia).
    /// </summary>
    public IEnumerable<CfgNode> BreadthFirstSearch()
    {
        if (EntryNodeId is null || !_nodes.ContainsKey(EntryNodeId))
            yield break;

        var visited = new HashSet<string>();
        var queue   = new Queue<string>();
        queue.Enqueue(EntryNodeId);
        visited.Add(EntryNodeId);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!_nodes.TryGetValue(current, out var node)) continue;
            yield return node;

            foreach (var successorId in node.Successors.Keys)
            {
                if (visited.Add(successorId))
                    queue.Enqueue(successorId);
            }
        }
    }

    /// <summary>
    /// Determina si el bloque <paramref name="targetId"/> es alcanzable
    /// desde el bloque <paramref name="sourceId"/>.
    /// </summary>
    public bool IsReachable(string sourceId, string targetId)
    {
        if (sourceId == targetId) return true;

        var visited = new HashSet<string>();
        var stack   = new Stack<string>();
        stack.Push(sourceId);

        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if (!visited.Add(current)) continue;
            if (current == targetId) return true;

            if (_nodes.TryGetValue(current, out var node))
                foreach (var s in node.Successors.Keys)
                    if (!visited.Contains(s)) stack.Push(s);
        }

        return false;
    }

    /// <summary>
    /// Encuentra todos los bloques en el camino desde source hasta target.
    /// Retorna null si no hay camino.
    /// </summary>
    public IReadOnlyList<string>? FindPath(string sourceId, string targetId)
    {
        if (sourceId == targetId) return [sourceId];

        var visited = new HashSet<string>();
        var queue   = new Queue<(string Id, List<string> Path)>();
        queue.Enqueue((sourceId, [sourceId]));

        while (queue.Count > 0)
        {
            var (current, path) = queue.Dequeue();
            if (!visited.Add(current)) continue;

            if (_nodes.TryGetValue(current, out var node))
            {
                foreach (var successorId in node.Successors.Keys)
                {
                    if (visited.Contains(successorId)) continue;

                    var newPath = new List<string>(path) { successorId };

                    if (successorId == targetId)
                        return newPath;

                    queue.Enqueue((successorId, newPath));
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Detecta bloques dentro de ciclos (while, for, foreach, do-while).
    /// </summary>
    public HashSet<string> DetectLoopBlocks()
    {
        var loopBlocks = new HashSet<string>();
        var visited    = new HashSet<string>();
        var inStack    = new HashSet<string>();

        void Dfs(string nodeId)
        {
            if (!visited.Add(nodeId)) return;
            inStack.Add(nodeId);

            if (_nodes.TryGetValue(nodeId, out var node))
            {
                foreach (var successorId in node.Successors.Keys)
                {
                    if (inStack.Contains(successorId))
                    {
                        MarkLoopBody(successorId, nodeId, loopBlocks);
                    }
                    else if (!visited.Contains(successorId))
                    {
                        Dfs(successorId);
                    }
                }
            }

            inStack.Remove(nodeId);
        }

        if (EntryNodeId is not null)
            Dfs(EntryNodeId);

        return loopBlocks;
    }

    private void MarkLoopBody(string headerNodeId, string backEdgeNodeId, HashSet<string> loopBlocks)
    {
        loopBlocks.Add(headerNodeId);

        var visited = new HashSet<string>();
        var queue   = new Queue<string>();
        queue.Enqueue(backEdgeNodeId);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!visited.Add(current)) continue;
            loopBlocks.Add(current);

            if (current == headerNodeId) continue;

            if (_nodes.TryGetValue(current, out var node))
                foreach (var predId in node.Predecessors)
                    if (!visited.Contains(predId)) queue.Enqueue(predId);
        }
    }

    // ── Conversión a ExportSchema ─────────────────────────────────────────────

    public MethodCfgExport ToExport() => new(
        MethodId:     MethodId,
        MethodName:   MethodName,
        Blocks: _nodes.Values.Select(n => new CfgBlockExport(
            BlockId:            n.BlockId,
            Kind:               n.Kind.ToString().ToLowerInvariant(),
            NodeIds:            n.SemanticNodeIds,
            LineStart:          n.LineStart,
            LineEnd:            n.LineEnd,
            BranchCondition:    n.BranchCondition,
            IsExceptionHandler: n.IsExceptionHandler
        )).ToList(),
        Edges: _edges.Select(e => new CfgEdgeExport(
            FromBlockId: e.FromId,
            ToBlockId:   e.ToId,
            EdgeKind:    e.Kind.ToString().ToLowerInvariant()
                         .Replace("truebranch", "true_branch")
                         .Replace("falsebranch", "false_branch")
        )).ToList(),
        EntryBlockId: EntryNodeId ?? string.Empty,
        ExitBlockIds: _exitNodeIds
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  NODO DEL CFG INTERNO (MUTABLE)
// ─────────────────────────────────────────────────────────────────────────────

public sealed class CfgNode
{
    public string BlockId              { get; }
    public CfgBlockKind Kind           { get; }
    public int LineStart               { get; }
    public int LineEnd                 { get; }
    public IReadOnlyList<string> SemanticNodeIds { get; }
    public string? BranchCondition    { get; }
    public bool IsExceptionHandler    { get; }

    public Dictionary<string, CfgEdgeKind> Successors   { get; } = [];
    public HashSet<string> Predecessors { get; } = [];

    public bool IsInLoop    { get; set; }
    public bool IsReachable { get; set; } = true;

    // Constructor posicional — los parámetros van EN ORDEN, sin nombres de record
    internal CfgNode(
        string blockId,
        CfgBlockKind kind,
        int lineStart,
        int lineEnd,
        IReadOnlyList<string> semanticNodeIds,
        string? branchCondition,
        bool isExceptionHandler)
    {
        BlockId             = blockId;
        Kind                = kind;
        LineStart           = lineStart;
        LineEnd             = lineEnd;
        SemanticNodeIds     = semanticNodeIds;
        BranchCondition     = branchCondition;
        IsExceptionHandler  = isExceptionHandler;
    }

    internal void AddSuccessor(string blockId, CfgEdgeKind edgeKind) =>
        Successors[blockId] = edgeKind;

    internal void AddPredecessor(string blockId) =>
        Predecessors.Add(blockId);

    public bool HasSuccessor(string targetBlockId) =>
        Successors.ContainsKey(targetBlockId);

    public IEnumerable<CfgEdgeKind> OutgoingEdgeKinds =>
        Successors.Values;

    public bool IsConditional =>
        Successors.Values.Any(k => k is CfgEdgeKind.TrueBranch or CfgEdgeKind.FalseBranch);

    public override string ToString() =>
        $"CfgNode({Kind}:{BlockId[..Math.Min(8, BlockId.Length)]}… " +
        $"L{LineStart}-{LineEnd}, " +
        $"{SemanticNodeIds.Count} nodes, {Successors.Count} successors)";
}

// ─────────────────────────────────────────────────────────────────────────────
//  ARISTA DEL CFG INTERNO
// ─────────────────────────────────────────────────────────────────────────────

public sealed record CfgEdge(
    string FromId,
    string ToId,
    CfgEdgeKind Kind
)
{
    public bool IsExceptionEdge =>
        Kind is CfgEdgeKind.Exception or CfgEdgeKind.Throw;

    public bool IsConditionalEdge =>
        Kind is CfgEdgeKind.TrueBranch or CfgEdgeKind.FalseBranch;

    public override string ToString() =>
        $"CfgEdge({FromId[..Math.Min(8, FromId.Length)]}… " +
        $"→[{Kind}]→ " +
        $"{ToId[..Math.Min(8, ToId.Length)]}…)";
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPERS DE ANÁLISIS DE BLOQUES
// ─────────────────────────────────────────────────────────────────────────────

public static class CfgNodeExtensions
{
    public static bool ContainsSink(this CfgNode block, IReadOnlyList<SemanticNode> allNodes)
    {
        var blockNodeIds = block.SemanticNodeIds.ToHashSet();
        return allNodes.Any(n =>
            blockNodeIds.Contains(n.NodeId) && n.IsKnownSink());
    }

    public static bool ContainsSanitizer(this CfgNode block, IReadOnlyList<SemanticNode> allNodes)
    {
        var blockNodeIds = block.SemanticNodeIds.ToHashSet();
        return allNodes.Any(n =>
            blockNodeIds.Contains(n.NodeId) && n.IsKnownSanitizer());
    }

    public static bool IsInExceptionHandler(this CfgNode block) =>
        block.IsExceptionHandler;
}