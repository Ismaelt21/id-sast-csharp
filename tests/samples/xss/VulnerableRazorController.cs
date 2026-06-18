// =============================================================
// SAMPLE: XSS via Html.Raw in Razor
// VULNERABILITY: XSS
// SEVERITY: HIGH
// CWE: CWE-79
// SOURCE: HttpRequest.Query["text"]
// SINK: Microsoft.AspNetCore.Html.HtmlString / Html.Raw
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Construye un HtmlString a partir de input del usuario y lo devuelve sin escapar
// =============================================================

using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Xss
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableRazorController : Controller
    {
        [HttpGet("render")]
        public IActionResult Render()
        {
            var raw = Request.Query["text"].ToString();

            // Vulnerable: wrap user input in HtmlString (equivalent to Html.Raw in view)
            var html = new HtmlString(raw);
            // Return as HTML content directly
            return Content(html.ToString(), "text/html");
        }
    }
}
