// =============================================================
// SAMPLE: Open Redirect control case
// VULNERABILITY: OPEN_REDIRECT
// SEVERITY: MEDIUM
// CWE: CWE-601
// SOURCE: HttpRequest.Query["returnUrl"]
// SINK: Microsoft.AspNetCore.Mvc.ControllerBase.LocalRedirect
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Solo permite rutas locales usando Url.IsLocalUrl
// =============================================================

using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedRedirectController : ControllerBase
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

            if (!Url.IsLocalUrl(returnUrl))
            {
                return BadRequest("External redirects not allowed");
            }

            return LocalRedirect(returnUrl);
        }
    }
}
