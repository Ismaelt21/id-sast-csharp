// =============================================================================
//  csharp-sast / roslyn_bridge / Program.cs
// =============================================================================
//
//  ENTRY POINT DEL ROSLYN BRIDGE — MINIMAL API
//  ─────────────────────────────────────────────
//  Conecta todos los extractores a un servidor HTTP ASP.NET Core.
//  El engine Python (roslyn_client.py) llama a estos endpoints.
//
//  ENDPOINTS:
//    POST /analyze      → análisis principal (SemanticExtractor + CfgExtractor + DfgExtractor)
//    GET  /health       → health check para scanner.py bridge --health
//    GET  /analyze/stats → estadísticas del último análisis (sin payload completo)
//    GET  /openapi/v1.json → schema OpenAPI para Swagger UI
//
//  ARQUITECTURA:
//    • ASP.NET Core 8 Minimal API (sin Controllers para mínimo overhead)
//    • Serilog para logging estructurado (JSON en producción)
//    • DI para todos los servicios (SemanticExtractor, CfgExtractor, etc.)
//    • CancellationToken propagado a todos los extractores
//    • Rate limiting para proteger el bridge en entornos compartidos
//    • Timeout configurable por análisis
//
//  CONFIGURACIÓN (variables de entorno / appsettings.json):
//    ROSLYN_BRIDGE_PORT            Puerto HTTP (default: 5100)
//    ROSLYN_BRIDGE_TIMEOUT_SECONDS Timeout por análisis en segundos (default: 300)
//    ROSLYN_BRIDGE_MAX_FILES       Máximo de archivos por request (default: 500)
//    ASPNETCORE_ENVIRONMENT        Development | Production
//
// =============================================================================

using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;
using RoslynBridge.Extractors;
using RoslynBridge.Models;
using RoslynBridge.Serializers;
using System.Threading.RateLimiting;

// ─────────────────────────────────────────────────────────────────────────────
//  BOOTSTRAP — SERILOG EARLY LOGGER
//  Serilog se configura antes del host para capturar errores de startup.
// ─────────────────────────────────────────────────────────────────────────────

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext} — {Message:lj}{NewLine}{Exception}"
    )
    .CreateBootstrapLogger();

Log.Information("Iniciando Roslyn Bridge v{Version}",
    typeof(Program).Assembly.GetName().Version);

// ─────────────────────────────────────────────────────────────────────────────
//  BUILDER
// ─────────────────────────────────────────────────────────────────────────────

var builder = WebApplication.CreateBuilder(args);

// ── Puerto desde variable de entorno o appsettings ───────────────────────────
var port = builder.Configuration.GetValue<int>("ROSLYN_BRIDGE_PORT", 5100);
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// ── Serilog completo ──────────────────────────────────────────────────────────
builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "RoslynBridge")
        .WriteTo.Console(
            outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext} — {Message:lj}{NewLine}{Exception}"
        )
        .WriteTo.File(
            path:           "logs/bridge-.log",
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 7,
            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {SourceContext} — {Message:lj}{NewLine}{Exception}"
        );

    // En producción usar JSON para integración con ELK/Datadog
    if (!context.HostingEnvironment.IsDevelopment())
        configuration.WriteTo.Console(new Serilog.Formatting.Json.JsonFormatter());
});

// ── Configuración de opciones ─────────────────────────────────────────────────
var bridgeConfig = builder.Configuration.GetSection("RoslynBridge");
var timeoutSeconds = bridgeConfig.GetValue<int>("TimeoutSeconds", 300);
var maxFiles       = bridgeConfig.GetValue<int>("MaxFiles", 500);
var isDevelopment  = builder.Environment.IsDevelopment();

// ── Registro de servicios DI ──────────────────────────────────────────────────

// Extractores — Scoped para que cada request tenga su instancia
// (SemanticExtractor mantiene estado interno de cache durante el análisis)
builder.Services.AddScoped<SemanticExtractor>();
builder.Services.AddScoped<CfgExtractor>();
builder.Services.AddScoped<DfgExtractor>();

// SymbolResolver — Singleton porque su cache es compartida y thread-safe
builder.Services.AddSingleton<SymbolResolver>();

// Serializador — Singleton (las opciones no cambian en runtime)
builder.Services.AddSingleton(_ => new AstSerializerOptions
{
    WriteIndented    = isDevelopment,
    EnableCompression = true,
    ValidateRoundTrip = isDevelopment,
});
builder.Services.AddSingleton<AstJsonSerializer>();

// ── Health Checks ──────────────────────────────────────────────────────────────
builder.Services.AddHealthChecks()
    .AddCheck("roslyn-bridge", () =>
    {
        // Verificar que las assemblies de Roslyn están cargadas correctamente
        var roslynAssembly = typeof(Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree).Assembly;
        return roslynAssembly is not null
            ? HealthCheckResult.Healthy($"Roslyn {roslynAssembly.GetName().Version} disponible")
            : HealthCheckResult.Unhealthy("Roslyn no disponible");
    }, tags: ["ready"]);

// ── Rate Limiting ──────────────────────────────────────────────────────────────
// Protege el bridge si se despliega en un entorno compartido.
// Un análisis SAST puede consumir mucha CPU; limitar a N análisis concurrentes.
builder.Services.AddRateLimiter(options =>
{
    options.AddConcurrencyLimiter("analysis-concurrency", config =>
    {
        config.PermitLimit   = bridgeConfig.GetValue<int>("MaxConcurrentAnalyses", 4);
        config.QueueLimit    = bridgeConfig.GetValue<int>("AnalysisQueueLimit", 8);
        config.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });

    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "El bridge está procesando el máximo de análisis concurrentes. " +
                    "Intenta de nuevo en unos segundos.",
            status = 503
        }, token);
    };
});

// ── OpenAPI / Swagger ──────────────────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title       = "Roslyn Bridge — csharp-sast",
        Version     = "v1",
        Description = "Bridge HTTP entre el engine SAST Python y el compilador Roslyn de C#."
    });
});

// ── CORS (solo en desarrollo, para pruebas desde el browser) ──────────────────
if (isDevelopment)
{
    builder.Services.AddCors(options =>
        options.AddDefaultPolicy(policy =>
            policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));
}

// ─────────────────────────────────────────────────────────────────────────────
//  BUILD Y MIDDLEWARE PIPELINE
// ─────────────────────────────────────────────────────────────────────────────

var app = builder.Build();

app.UseSerilogRequestLogging(opts =>
{
    opts.MessageTemplate =
        "HTTP {RequestMethod} {RequestPath} → {StatusCode} en {Elapsed:F0}ms";
});

app.UseRateLimiter();

if (isDevelopment)
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Roslyn Bridge v1");
        c.RoutePrefix = "swagger";
    });
    app.UseCors();
}

// ─────────────────────────────────────────────────────────────────────────────
//  ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /health ───────────────────────────────────────────────────────────────
// El scanner.py llama aquí antes de iniciar el análisis para verificar
// que el bridge está disponible.

app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = async (context, report) =>
    {
        var roslynVersion = typeof(Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree)
            .Assembly.GetName().Version?.ToString() ?? "unknown";

        var response = new HealthResponse(
            Status:        report.Status.ToString().ToLowerInvariant(),
            Version:       app.Services.GetRequiredService<IHostEnvironment>().ApplicationName + " "
                           + typeof(Program).Assembly.GetName().Version,
            DotnetVersion: Environment.Version.ToString(),
            RoslynVersion: roslynVersion,
            Timestamp:     DateTime.UtcNow.ToString("O")
        );

        context.Response.ContentType = "application/json";
        context.Response.StatusCode  = report.Status == HealthStatus.Healthy
            ? StatusCodes.Status200OK
            : StatusCodes.Status503ServiceUnavailable;

        await context.Response.WriteAsJsonAsync(
            response,
            RoslynBridgeJsonContext.Default.HealthResponse
        );
    }
});

// ── POST /analyze ─────────────────────────────────────────────────────────────
// Endpoint principal del bridge.
// El engine Python (roslyn_client.py) envía aquí los archivos .cs
// y recibe el JSON del modelo semántico.

app.MapPost("/analyze", async (
    HttpContext httpContext,
    SemanticExtractor semanticExtractor,
    CfgExtractor cfgExtractor,
    DfgExtractor dfgExtractor,
    AstJsonSerializer serializer,
    ILogger<Program> logger,
    IConfiguration config) =>
{
    // ── 1. Deserializar el request ────────────────────────────────────────────
    AnalysisRequest request;
    try
    {
        request = await serializer.DeserializeRequestAsync(
            httpContext.Request.Body,
            httpContext.RequestAborted
        );
    }
    catch (JsonException ex)
    {
        logger.LogWarning("Request JSON inválido: {Error}", ex.Message);
        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            error   = "JSON del request inválido.",
            details = ex.Message,
            status  = 400
        });
        return;
    }

    // ── 2. Validar el request ─────────────────────────────────────────────────
    if (request.Files.Count == 0)
    {
        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            error  = "El campo 'files' no puede estar vacío.",
            status = 400
        });
        return;
    }

    var maxFilesAllowed = config.GetValue<int>("RoslynBridge:MaxFiles", 500);
    if (request.Files.Count > maxFilesAllowed)
    {
        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            error  = $"Demasiados archivos: {request.Files.Count}. Máximo: {maxFilesAllowed}.",
            status = 400
        });
        return;
    }

    // ── 3. Configurar timeout ─────────────────────────────────────────────────
    var timeoutSecs = config.GetValue<int>("RoslynBridge:TimeoutSeconds", 300);
    using var timeoutCts  = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSecs));
    using var linkedCts   = CancellationTokenSource.CreateLinkedTokenSource(
        httpContext.RequestAborted, timeoutCts.Token);
    var ct = linkedCts.Token;

    logger.LogInformation(
        "Análisis iniciado: {FileCount} archivo(s), timeout: {Timeout}s",
        request.Files.Count, timeoutSecs);

    // ── 4. Pipeline de extracción ─────────────────────────────────────────────
    RoslynExportRoot exportRoot;
    try
    {
        // 4a. Extracción semántica principal
        exportRoot = await semanticExtractor.ExtractAsync(request, ct);

        // 4b. Para construir el CFG y DFG necesitamos la compilación.
        //     SemanticExtractor la construye internamente; la reconstruimos
        //     aquí con los mismos parámetros para CfgExtractor y DfgExtractor.
        //     En una versión futura se puede refactorizar para compartirla via DI.
        var (compilation, syntaxTrees) = await RebuildCompilationAsync(request, ct);

        // 4c. Extracción del CFG
        var controlFlow = await cfgExtractor.ExtractAsync(
            exportRoot, compilation, syntaxTrees, ct);

        // 4d. Enriquecimiento del DFG
        var dataFlow = await dfgExtractor.EnrichAsync(
            exportRoot, compilation, syntaxTrees, ct);

        // 4e. Ensamblar el export final con CFG y DFG enriquecidos
        exportRoot = exportRoot with
        {
            ControlFlow = controlFlow,
            DataFlow    = dataFlow,
        };
    }
    catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
    {
        logger.LogError(
            "Análisis cancelado por timeout ({Timeout}s). Archivos: {Files}",
            timeoutSecs, string.Join(", ", request.Files.Take(3)));

        httpContext.Response.StatusCode = StatusCodes.Status408RequestTimeout;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            error   = $"El análisis excedió el timeout de {timeoutSecs} segundos.",
            files   = request.Files.Count,
            status  = 408,
        });
        return;
    }
    catch (OperationCanceledException)
    {
        logger.LogInformation("Análisis cancelado por el cliente.");
        return;
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error inesperado durante el análisis.");
        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            error   = "Error interno durante el análisis semántico.",
            details = app.Environment.IsDevelopment() ? ex.ToString() : ex.Message,
            status  = 500,
        });
        return;
    }

    // ── 5. Serializar y enviar la respuesta ───────────────────────────────────
    httpContext.Response.ContentType = "application/json; charset=utf-8";

    var compressed = await serializer.SerializeToStreamAsync(
        exportRoot,
        httpContext.Response.Body,
        ct
    );

    if (compressed)
        httpContext.Response.Headers["Content-Encoding"] = "gzip";

    logger.LogInformation(
        "Análisis completado: {Nodes} nodos semánticos, {Classes} clases, " +
        "{CfgMethods} métodos con CFG, comprimido: {Compressed}",
        exportRoot.SemanticNodes.Count,
        exportRoot.CompilationUnit.Classes.Count,
        exportRoot.ControlFlow.Methods.Count,
        compressed);
})
.WithName("AnalyzeCode")
.WithSummary("Analiza archivos C# con Roslyn y retorna el modelo semántico como JSON")
.WithDescription(
    "Recibe una lista de rutas de archivos .cs, los compila en memoria con Roslyn, " +
    "extrae AST semántico + CFG + DFG y retorna un JSON estructurado para el engine Python.")
.Produces<RoslynExportRoot>(StatusCodes.Status200OK, "application/json")
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status408RequestTimeout)
.Produces(StatusCodes.Status503ServiceUnavailable)
.Produces(StatusCodes.Status500InternalServerError)
.RequireRateLimiting("analysis-concurrency");

// ── GET /analyze/stats ────────────────────────────────────────────────────────
// Devuelve estadísticas sin el payload completo.
// Útil para monitoreo y para verificar que el análisis produjo resultados.

app.MapGet("/analyze/stats", (AstJsonSerializer serializer) =>
{
    // En producción real esto devolvería las stats del último análisis
    // cacheado en IMemoryCache. Para el MVP devolvemos info estática.
    return Results.Ok(new
    {
        bridge_version  = typeof(Program).Assembly.GetName().Version?.ToString(),
        roslyn_version  = typeof(Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree)
                              .Assembly.GetName().Version?.ToString(),
        dotnet_version  = Environment.Version.ToString(),
        endpoints       = new[] { "POST /analyze", "GET /health", "GET /analyze/stats" },
        status          = "ready"
    });
})
.WithName("GetBridgeStats")
.WithSummary("Información y estadísticas del bridge");

// ── GET / ─────────────────────────────────────────────────────────────────────
// Landing page del bridge (útil cuando se abre en el browser en desarrollo).

app.MapGet("/", () => Results.Redirect(isDevelopment ? "/swagger" : "/health"))
   .ExcludeFromDescription();

// ─────────────────────────────────────────────────────────────────────────────
//  ARRANQUE
// ─────────────────────────────────────────────────────────────────────────────

Log.Information("Roslyn Bridge escuchando en: http://0.0.0.0:{Port}", port);
Log.Information("Swagger UI: http://localhost:{Port}/swagger (solo en Development)", port);

try
{
    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "El Roslyn Bridge terminó inesperadamente.");
    throw;
}
finally
{
    Log.CloseAndFlush();
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPER: RECONSTRUCCIÓN DE LA COMPILACIÓN
//  En una versión futura se puede compartir la compilación via IMemoryCache.
// ─────────────────────────────────────────────────────────────────────────────

static async Task<(Microsoft.CodeAnalysis.CSharp.CSharpCompilation, List<Microsoft.CodeAnalysis.SyntaxTree>)>
    RebuildCompilationAsync(AnalysisRequest request, CancellationToken ct)
{
    var trees = new List<Microsoft.CodeAnalysis.SyntaxTree>();

    foreach (var file in request.Files)
    {
        ct.ThrowIfCancellationRequested();
        if (!File.Exists(file)) continue;

        var source = await File.ReadAllTextAsync(file, ct);
        trees.Add(Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree.ParseText(
            source,
            new Microsoft.CodeAnalysis.CSharp.CSharpParseOptions(
                Microsoft.CodeAnalysis.CSharp.LanguageVersion.Latest),
            path: file
        ));
    }

    // Referencias mínimas del BCL para que Roslyn pueda resolver tipos
    var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
    var references = new List<Microsoft.CodeAnalysis.MetadataReference>();

    var coreAsms = new[] {
        "System.Private.CoreLib.dll", "System.Runtime.dll",
        "System.Collections.dll", "System.Linq.dll",
        "System.Net.Http.dll", "System.Private.Uri.dll", "System.Xml.dll",
        "System.Data.Common.dll", "netstandard.dll"
    };

    foreach (var asm in coreAsms)
    {
        var path = Path.Combine(runtimeDir, asm);
        if (File.Exists(path))
            references.Add(Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(path));
    }

    var compilation = Microsoft.CodeAnalysis.CSharp.CSharpCompilation.Create(
        "CSharpSastAnalysis",
        syntaxTrees: trees,
        references:  references,
        options: new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(
            Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary)
    );

    return (compilation, trees);
}
