// =============================================================
// SAMPLE: Open Redirect via Redirect(returnUrl)
// VULNERABILITY: OPEN_REDIRECT
// SEVERITY: MEDIUM
// CWE: CWE-601
// SOURCE: HttpRequest.Query["returnUrl"]
// SINK: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Redirige a la URL proporcionada por el usuario sin validación
// =============================================================

using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.OpenRedirect
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableRedirectController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult Login()
        {
            var returnUrl = Request.Query["returnUrl"].ToString();
            return Redirect(returnUrl);
        }
    }
}
