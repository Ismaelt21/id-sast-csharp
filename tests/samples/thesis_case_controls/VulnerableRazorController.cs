// =============================================================
// SAMPLE: XSS control case
// VULNERABILITY: XSS
// SEVERITY: HIGH
// CWE: CWE-79
// SOURCE: HttpRequest.Query["text"]
// SINK: Microsoft.AspNetCore.Html.HtmlString
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Construye HTML con input del usuario sin encoding
// =============================================================

using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableRazorController : Controller
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

            var html = new HtmlString(
                "<section class=\"card card-" + theme + "\">" +
                "<h2>" + text + "</h2>" +
                "</section>");

            return new ContentResult
            {
                Content = html.ToString(),
                ContentType = "text/html"
            };
        }
    }
}
