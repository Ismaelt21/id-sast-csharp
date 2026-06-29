// =============================================================
// SAMPLE: XSS control case
// VULNERABILITY: XSS
// SEVERITY: HIGH
// CWE: CWE-79
// SOURCE: HttpRequest.Query["text"]
// SINK: Microsoft.AspNetCore.Html.HtmlString
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Encoda explícitamente el contenido antes de devolver HTML
// =============================================================

using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedRazorController : Controller
    {
        [HttpGet("render")]
        public IActionResult Render()
        {
            var text = Request.Query["text"].ToString();
            var theme = Request.Query["theme"].ToString();
            if (string.IsNullOrWhiteSpace(theme))
            {
                theme = "default";
            }

            var safeText = WebUtility.HtmlEncode(text);
            var safeTheme = WebUtility.HtmlEncode(theme);
            var html = "<section class=\"card card-" + safeTheme + "\">" +
                       "<h2>" + safeText + "</h2>" +
                       "</section>";

            return new ContentResult
            {
                Content = html,
                ContentType = "text/html"
            };
        }
    }
}
