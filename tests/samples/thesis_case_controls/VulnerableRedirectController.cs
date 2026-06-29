// =============================================================
// SAMPLE: Open Redirect control case
// VULNERABILITY: OPEN_REDIRECT
// SEVERITY: MEDIUM
// CWE: CWE-601
// SOURCE: HttpRequest.Query["returnUrl"]
// SINK: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Redirige a una URL provista por el usuario sin validar
// =============================================================

using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableRedirectController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult Login()
        {
            var returnUrl = Request.Query["returnUrl"].ToString();
            var source = Request.Query["source"].ToString();
            if (!string.IsNullOrWhiteSpace(source))
            {
                returnUrl = returnUrl.Trim();
            }

            return Redirect(returnUrl);
        }
    }
}
