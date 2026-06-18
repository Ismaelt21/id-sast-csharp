// =============================================================================
//  csharp-sast / roslyn_bridge / Serializers / AstJsonSerializer.cs
// =============================================================================
//
//  SERIALIZADOR JSON DEL MODELO SEMÁNTICO
//  ────────────────────────────────────────
//  Convierte RoslynExportRoot → JSON que consume el engine Python.
//
//  ESTRATEGIA DE SERIALIZACIÓN:
//    System.Text.Json con Source Generators (JsonSerializerContext).
//    Los source generators generan código de serialización en compile-time,
//    eliminando la reflexión en runtime → ~2-3x más rápido y menos memoria
//    que Newtonsoft.Json o System.Text.Json con reflexión.
//
//  POR QUÉ ESTO IMPORTA PARA EL SAST:
//    El export JSON puede ser grande (proyectos con 500+ archivos .cs
//    pueden generar exports de 50-200 MB). La serialización eficiente
//    es crítica para que el bridge no sea el bottleneck del pipeline.
//
//  FORMATO DE SALIDA:
//    • snake_case en todas las propiedades (para Python)
//    • Nulls omitidos para reducir tamaño del JSON
//    • Indentado configurable (debug: indentado, producción: minificado)
//    • Encoding: UTF-8 sin BOM
//
//  COMPRESIÓN OPCIONAL:
//    Si el JSON supera COMPRESSION_THRESHOLD_BYTES, se comprime con GZip.
//    El engine Python (roslyn_client.py) descomprime automáticamente
//    verificando el Content-Encoding: gzip del response HTTP.
//
// =============================================================================

using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RoslynBridge.Models;

namespace RoslynBridge.Serializers;

// ─────────────────────────────────────────────────────────────────────────────
//  SOURCE GENERATOR CONTEXT
//  Genera código de serialización en compile-time para todos los tipos
//  del ExportSchema, eliminando la reflexión en runtime.
// ─────────────────────────────────────────────────────────────────────────────

[JsonSerializable(typeof(RoslynExportRoot))]
[JsonSerializable(typeof(ExportMetadata))]
[JsonSerializable(typeof(CompilationErrorExport))]
[JsonSerializable(typeof(CompilationUnit))]
[JsonSerializable(typeof(ClassExport))]
[JsonSerializable(typeof(MethodExport))]
[JsonSerializable(typeof(ParameterExport))]
[JsonSerializable(typeof(FieldExport))]
[JsonSerializable(typeof(PropertyExport))]
[JsonSerializable(typeof(SemanticNode))]
[JsonSerializable(typeof(ArgumentExport))]
[JsonSerializable(typeof(ControlFlowExport))]
[JsonSerializable(typeof(MethodCfgExport))]
[JsonSerializable(typeof(CfgBlockExport))]
[JsonSerializable(typeof(CfgEdgeExport))]
[JsonSerializable(typeof(DataFlowExport))]
[JsonSerializable(typeof(AssignmentExport))]
[JsonSerializable(typeof(ParameterFlowExport))]
[JsonSerializable(typeof(ReturnFlowExport))]
[JsonSerializable(typeof(SymbolsExport))]
[JsonSerializable(typeof(ExternalCallExport))]
[JsonSerializable(typeof(AttributeAnnotation))]
[JsonSerializable(typeof(AnalysisRequest))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(SerializationStats))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true, WriteIndented = false)]
internal partial class RoslynBridgeJsonContext : JsonSerializerContext { }

// ─────────────────────────────────────────────────────────────────────────────
//  SERIALIZADOR PRINCIPAL
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Serializa el RoslynExportRoot a JSON listo para el engine Python.
/// Soporta serialización a string, stream y bytes, con compresión GZip opcional.
/// </summary>
public sealed class AstJsonSerializer
{
    // Umbral de compresión: si el JSON supera este tamaño, se comprime.
    // 512 KB es el punto donde la compresión GZip empieza a ser rentable
    // comparado con el overhead de comprimir.
    private const int CompressionThresholdBytes = 512 * 1024;

    // Nivel de compresión: Optimal da mejor ratio, Fastest es más rápido.
    // Para SAST se prefiere Optimal porque el JSON puede ser muy grande.
    private const CompressionLevel DefaultCompressionLevel = CompressionLevel.Optimal;

    private readonly ILogger<AstJsonSerializer> _logger;
    private readonly AstSerializerOptions _options;

    // Opciones de System.Text.Json con y sin indentado
    private readonly JsonSerializerOptions _productionOptions;
    private readonly JsonSerializerOptions _debugOptions;

    public AstJsonSerializer(
        ILogger<AstJsonSerializer> logger,
        AstSerializerOptions? options = null)
    {
        _logger  = logger;
        _options = options ?? new AstSerializerOptions();

        _productionOptions = BuildJsonOptions(writeIndented: false);
        _debugOptions      = BuildJsonOptions(writeIndented: true);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  SERIALIZACIÓN A STREAM (más eficiente para HTTP responses grandes)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Serializa el export al stream de respuesta HTTP.
    /// Método principal usado por Program.cs en el endpoint POST /analyze.
    ///
    /// Si el JSON resultante supera el umbral de compresión:
    ///   • Escribe el JSON en un buffer intermedio
    ///   • Comprime con GZip y escribe al stream de salida
    ///   • Retorna true para que Program.cs añada Content-Encoding: gzip
    ///
    /// Si no supera el umbral:
    ///   • Serializa directamente al stream de salida
    ///   • Retorna false (sin compresión)
    /// </summary>
    /// <param name="export">El modelo a serializar.</param>
    /// <param name="outputStream">Stream de salida (HTTP response body).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>true si el output está comprimido con GZip, false si no.</returns>
    public async Task<bool> SerializeToStreamAsync(
        RoslynExportRoot export,
        Stream outputStream,
        CancellationToken cancellationToken = default)
    {
        var jsonOptions = _options.WriteIndented ? _debugOptions : _productionOptions;
        var startTime   = DateTime.UtcNow;

        // Serializar a un buffer en memoria para medir el tamaño
        using var buffer = new MemoryStream();
        await JsonSerializer.SerializeAsync(
            buffer,
            export,
            RoslynBridgeJsonContext.Default.RoslynExportRoot,
            cancellationToken
        );

        var jsonSizeBytes = buffer.Length;
        var elapsed       = (DateTime.UtcNow - startTime).TotalMilliseconds;

        _logger.LogInformation(
            "JSON serializado: {Size:F1} KB en {Elapsed:F0} ms",
            jsonSizeBytes / 1024.0, elapsed);

        // Decidir si comprimir
        bool compressed = false;

        if (_options.EnableCompression && jsonSizeBytes >= CompressionThresholdBytes)
        {
            compressed = true;
            buffer.Seek(0, SeekOrigin.Begin);

            var compressStart = DateTime.UtcNow;
            await using var gzip = new GZipStream(outputStream, DefaultCompressionLevel, leaveOpen: true);
            await buffer.CopyToAsync(gzip, cancellationToken);
            await gzip.FlushAsync(cancellationToken);

            var compressElapsed = (DateTime.UtcNow - compressStart).TotalMilliseconds;
            _logger.LogInformation(
                "JSON comprimido con GZip: {Original:F1} KB → {CompressedEstimate} ms",
                jsonSizeBytes / 1024.0, compressElapsed);
        }
        else
        {
            buffer.Seek(0, SeekOrigin.Begin);
            await buffer.CopyToAsync(outputStream, cancellationToken);
        }

        return compressed;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  SERIALIZACIÓN A STRING (para tests y debug)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Serializa el export a string JSON.
    /// Usar principalmente en tests unitarios y en el endpoint de debug.
    /// Para producción preferir SerializeToStreamAsync (no carga todo en memoria).
    /// </summary>
    public string SerializeToString(RoslynExportRoot export, bool indented = false)
    {
        var jsonOptions = indented ? _debugOptions : _productionOptions;

        var json = JsonSerializer.Serialize(
            export,
            RoslynBridgeJsonContext.Default.RoslynExportRoot
        );

        _logger.LogDebug("JSON serializado a string: {Size:F1} KB", json.Length / 1024.0);
        return json;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  SERIALIZACIÓN A BYTES (para caching y testing)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Serializa el export a bytes UTF-8.
    /// Útil para caching en memoria (IMemoryCache) y para tests de integración.
    /// </summary>
    public byte[] SerializeToBytes(RoslynExportRoot export)
    {
        return JsonSerializer.SerializeToUtf8Bytes(
            export,
            RoslynBridgeJsonContext.Default.RoslynExportRoot
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  DESERIALIZACIÓN DEL REQUEST (AnalysisRequest desde Python)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Deserializa el AnalysisRequest enviado por el engine Python.
    /// Lanza JsonException si el formato es incorrecto.
    /// </summary>
    public async Task<AnalysisRequest> DeserializeRequestAsync(
        Stream inputStream,
        CancellationToken cancellationToken = default)
    {
        var request = await JsonSerializer.DeserializeAsync(
            inputStream,
            RoslynBridgeJsonContext.Default.AnalysisRequest,
            cancellationToken
        );

        return request ?? throw new JsonException("El request deserializado es null.");
    }

    /// <summary>
    /// Deserializa un AnalysisRequest desde un string JSON.
    /// Usado en tests unitarios.
    /// </summary>
    public AnalysisRequest DeserializeRequest(string json)
    {
        var request = JsonSerializer.Deserialize(
            json,
            RoslynBridgeJsonContext.Default.AnalysisRequest
        );

        return request ?? throw new JsonException("El request deserializado es null.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  ESTADÍSTICAS DEL EXPORT (para el endpoint de debug)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Genera estadísticas del export sin serializar el objeto completo.
    /// Usado por el endpoint GET /analyze/stats.
    /// </summary>
    public string SerializeStats(RoslynExportRoot export)
    {
        var stats = new SerializationStats(
            FilesAnalyzed:        export.Metadata.Files.Count,
            ClassesFound:         export.CompilationUnit.Classes.Count,
            MethodsFound:         export.CompilationUnit.Classes.Sum(c => c.Methods.Count),
            SemanticNodes:        export.SemanticNodes.Count,
            SinkNodes:            export.SemanticNodes.Count(n => n.IsKnownSink()),
            SourceNodes:          export.SemanticNodes.Count(n => n.IsKnownSource()),
            CfgMethods:           export.ControlFlow.Methods.Count,
            TotalCfgBlocks:       export.ControlFlow.Methods.Sum(m => m.Blocks.Count),
            TotalCfgEdges:        export.ControlFlow.Methods.Sum(m => m.Edges.Count),
            Assignments:          export.DataFlow.Assignments.Count,
            ParameterFlows:       export.DataFlow.ParameterFlows.Count,
            ExternalCalls:        export.Symbols.ExternalCalls.Count,
            AttributeAnnotations: export.Symbols.AttributeAnnotations.Count,
            FrameworkDetected:    export.Metadata.FrameworkDetected ?? "generic",
            LanguageVersion:      export.Metadata.LanguageVersion,
            CompilationErrors:    export.Metadata.CompilationErrors.Count,
            AnalysisTimestamp:    export.Metadata.AnalysisTimestamp
        );

        return JsonSerializer.Serialize(
            stats,
            RoslynBridgeJsonContext.Default.SerializationStats
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  VALIDACIÓN DEL JSON EXPORTADO
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Valida que el JSON exportado puede ser correctamente deserializado.
    /// Se ejecuta en modo Debug para detectar errores de serialización temprano.
    /// En producción está deshabilitado por performance.
    /// </summary>
    public bool ValidateRoundTrip(RoslynExportRoot export)
    {
        try
        {
            var json         = SerializeToBytes(export);
            var deserialized = JsonSerializer.Deserialize(
                json,
                RoslynBridgeJsonContext.Default.RoslynExportRoot
            );

            var isValid = deserialized is not null
                && deserialized.SemanticNodes.Count == export.SemanticNodes.Count
                && deserialized.CompilationUnit.Classes.Count == export.CompilationUnit.Classes.Count;

            if (!isValid)
                _logger.LogWarning("Round-trip validation fallida: conteos de nodos no coinciden.");

            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error en round-trip validation del JSON export.");
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  CONFIGURACIÓN INTERNA
    // ─────────────────────────────────────────────────────────────────────────

    private static JsonSerializerOptions BuildJsonOptions(bool writeIndented) =>
        new()
        {
            WriteIndented           = writeIndented,
            DefaultIgnoreCondition  = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy    = new JsonSnakeCaseNamingPolicy(),
            AllowTrailingCommas     = true,
            ReadCommentHandling     = JsonCommentHandling.Skip,
            // Evitar referencias circulares (el CFG puede tener ciclos internos)
            ReferenceHandler        = ReferenceHandler.IgnoreCycles,
            // Encoding UTF-8 sin BOM para compatibilidad con Python json.loads()
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
}

// ─────────────────────────────────────────────────────────────────────────────
//  MODELOS AUXILIARES DEL SERIALIZADOR
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Naming policy para convertir nombres a snake_case (ej: MyProperty -> my_property).
/// Implementación simple y suficiente para serializar a JSON compatible con Python.
/// </summary>
internal sealed class JsonSnakeCaseNamingPolicy : JsonNamingPolicy
{
    public override string ConvertName(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;

        var sb = new StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                // prepend underscore if not first and previous is not underscore
                if (i > 0 && name[i - 1] != '_') sb.Append('_');
                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}

/// <summary>
/// Opciones de configuración del serializador.
/// Se registran en DI en Program.cs.
/// </summary>
public sealed class AstSerializerOptions
{
    /// <summary>
    /// Si true, el JSON se escribe con indentado (legible).
    /// Default: false (producción, más compacto).
    /// Activado automáticamente si la variable de entorno ASPNETCORE_ENVIRONMENT = Development.
    /// </summary>
    public bool WriteIndented { get; init; } = false;

    /// <summary>
    /// Si true, comprime el JSON con GZip cuando supera el umbral.
    /// Default: true.
    /// </summary>
    public bool EnableCompression { get; init; } = true;

    /// <summary>
    /// Si true, ejecuta ValidateRoundTrip() después de serializar.
    /// Solo en modo Debug. Default: false.
    /// </summary>
    public bool ValidateRoundTrip { get; init; } = false;
}

/// <summary>
/// Estadísticas del export JSON.
/// Devueltas por el endpoint GET /analyze/stats sin el payload completo.
/// </summary>
public sealed record SerializationStats(
    [property: JsonPropertyName("files_analyzed")]
    int FilesAnalyzed,

    [property: JsonPropertyName("classes_found")]
    int ClassesFound,

    [property: JsonPropertyName("methods_found")]
    int MethodsFound,

    [property: JsonPropertyName("semantic_nodes")]
    int SemanticNodes,

    [property: JsonPropertyName("sink_nodes")]
    int SinkNodes,

    [property: JsonPropertyName("source_nodes")]
    int SourceNodes,

    [property: JsonPropertyName("cfg_methods")]
    int CfgMethods,

    [property: JsonPropertyName("total_cfg_blocks")]
    int TotalCfgBlocks,

    [property: JsonPropertyName("total_cfg_edges")]
    int TotalCfgEdges,

    [property: JsonPropertyName("assignments")]
    int Assignments,

    [property: JsonPropertyName("parameter_flows")]
    int ParameterFlows,

    [property: JsonPropertyName("external_calls")]
    int ExternalCalls,

    [property: JsonPropertyName("attribute_annotations")]
    int AttributeAnnotations,

    [property: JsonPropertyName("framework_detected")]
    string FrameworkDetected,

    [property: JsonPropertyName("language_version")]
    string LanguageVersion,

    [property: JsonPropertyName("compilation_errors")]
    int CompilationErrors,

    [property: JsonPropertyName("analysis_timestamp")]
    string AnalysisTimestamp
);