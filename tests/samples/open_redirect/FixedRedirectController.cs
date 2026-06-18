// =============================================================
// SAMPLE: Open Redirect via Redirect(returnUrl)
// VULNERABILITY: OPEN_REDIRECT
// SEVERITY: MEDIUM
// CWE: CWE-601
// SOURCE: HttpRequest.Query["returnUrl"]
// SINK: Microsoft.AspNetCore.Mvc.ControllerBase.LocalRedirect
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa Url.IsLocalUrl o LocalRedirect para evitar open redirect
// =============================================================

using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.OpenRedirect
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedRedirectController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult Login()
        {
            var returnUrl = Request.Query["returnUrl"].ToString();
            if (!Url.IsLocalUrl(returnUrl)) return BadRequest("External redirects not allowed");
            return LocalRedirect(returnUrl);
        }
    }
}
