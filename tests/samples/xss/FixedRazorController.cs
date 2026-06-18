// =============================================================
// SAMPLE: XSS via Html.Raw in Razor
// VULNERABILITY: XSS
// SEVERITY: HIGH
// CWE: CWE-79
// SOURCE: HttpRequest.Query["text"]
// SINK: Microsoft.AspNetCore.Html.HtmlString / Html.Raw
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Deja que Razor haga el escape automático o codifica explícitamente
// =============================================================

using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Xss
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedRazorController : Controller
    {
        [HttpGet("render")]
        public IActionResult Render()
        {
            var raw = Request.Query["text"].ToString();

            // Fix: explicitly encode user input and return safe HTML or return view and allow Razor to escape
            var safe = HtmlEncoder.Default.Encode(raw);
            return Content(safe, "text/html");
        }
    }
}
