// =============================================================
// SAMPLE: Command Injection via Process.Start
// VULNERABILITY: COMMAND_INJECTION
// SEVERITY: CRITICAL
// CWE: CWE-77
// SOURCE: HttpRequest.Query["arg"]
// SINK: System.Diagnostics.Process.Start
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Construye argumentos concatenados y ejecuta un proceso
// =============================================================

using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.CommandInjection
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableCommandService : ControllerBase
    {
        [HttpGet("run")]
        public IActionResult Run()
        {
            var arg = Request.Query["arg"].ToString();
            // Vulnerable: concatenation into shell command
            var cmd = "ping " + arg;
            Process.Start("cmd.exe", "/c " + cmd);
            return Ok("started");
        }
    }
}
