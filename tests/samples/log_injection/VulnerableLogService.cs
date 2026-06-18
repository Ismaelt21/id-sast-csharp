// =============================================================
// SAMPLE: Log Injection via ILogger
// VULNERABILITY: LOG_INJECTION
// SEVERITY: LOW
// CWE: CWE-117
// SOURCE: HttpRequest.Query["msg"]
// SINK: ILogger.LogInformation
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Construye un mensaje de log concatenando input del usuario
// =============================================================

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Tests.Samples.LogInjection
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableLogService : ControllerBase
    {
        private readonly ILogger<VulnerableLogService> _logger;

        public VulnerableLogService(ILogger<VulnerableLogService> logger)
        {
            _logger = logger;
        }

        [HttpGet("info")]
        public IActionResult Info()
        {
            var msg = Request.Query["msg"].ToString();
            // Vulnerable: string concatenation into logs
            _logger.LogInformation("User message: " + msg);
            return Ok();
        }
    }
}
