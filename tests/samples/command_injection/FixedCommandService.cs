// =============================================================
// SAMPLE: Command Injection via Process.Start
// VULNERABILITY: COMMAND_INJECTION
// SEVERITY: CRITICAL
// CWE: CWE-77
// SOURCE: HttpRequest.Query["arg"]
// SINK: System.Diagnostics.Process.Start
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa ProcessStartInfo.ArgumentList para separar comando y argumentos
// =============================================================

using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.CommandInjection
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedCommandService : ControllerBase
    {
        [HttpGet("run")]
        public IActionResult Run()
        {
            var arg = Request.Query["arg"].ToString();

            var psi = new ProcessStartInfo
            {
                FileName = "ping",
                UseShellExecute = false
            };
            // Add the argument as a separate token
            psi.ArgumentList.Add(arg);
            Process.Start(psi);
            return Ok("started");
        }
    }
}
