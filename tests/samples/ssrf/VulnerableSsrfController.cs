// =============================================================
// SAMPLE: SSRF via HttpClient.GetAsync
// VULNERABILITY: SSRF
// SEVERITY: HIGH
// CWE: CWE-918
// SOURCE: HttpRequest.Query["url"]
// SINK: System.Net.Http.HttpClient.GetAsync
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Realiza una petición HTTP a una URL suministrada por el usuario
// =============================================================

using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Ssrf
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
            // Vulnerable: no validation of remote host
            var resp = _http.GetAsync(url).Result;
            var body = resp.Content.ReadAsStringAsync().Result;
            return Ok(new { Body = body });
        }
    }
}
