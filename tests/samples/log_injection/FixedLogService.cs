// =============================================================
// SAMPLE: Log Injection via ILogger
// VULNERABILITY: LOG_INJECTION
// SEVERITY: LOW
// CWE: CWE-117
// SOURCE: HttpRequest.Query["msg"]
// SINK: ILogger.LogInformation
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa structured logging para evitar inyección de logs
// =============================================================

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Tests.Samples.LogInjection
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedLogService : ControllerBase
    {
        private readonly ILogger<FixedLogService> _logger;

        public FixedLogService(ILogger<FixedLogService> logger)
        {
            _logger = logger;
        }

        [HttpGet("info")]
        public IActionResult Info()
        {
            var msg = Request.Query["msg"].ToString();
            // Fix: use structured logging with parameterized message
            _logger.LogInformation("User message: {Message}", msg);
            return Ok();
        }
    }
}
