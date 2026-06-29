// =============================================================
// SAMPLE: SSRF control case
// VULNERABILITY: SSRF
// SEVERITY: HIGH
// CWE: CWE-918
// SOURCE: HttpRequest.Query["url"]
// SINK: System.Net.Http.HttpClient.GetAsync
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Solicita contenido a una URL controlada por el usuario
// =============================================================

using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableSsrfController : ControllerBase
    {
        private static readonly HttpClient _http = new HttpClient();

        [HttpGet("fetch")]
        public IActionResult Fetch()
        {
            var url = Request.Query["url"].ToString();
            var mode = Request.Query["mode"].ToString();
            if (!string.IsNullOrWhiteSpace(mode))
            {
                url = url.Trim();
            }

            var resp = _http.GetAsync(url).Result;
            var body = resp.Content.ReadAsStringAsync().Result;
            return Ok(new { Body = body });
        }
    }
}
