// =============================================================
// SAMPLE: SSRF control case
// VULNERABILITY: SSRF
// SEVERITY: HIGH
// CWE: CWE-918
// SOURCE: HttpRequest.Query["url"]
// SINK: System.Net.Http.HttpClient.GetAsync
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Valida la URL y limita el host a una lista permitida
// =============================================================

using System;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedSsrfController : ControllerBase
    {
        private static readonly HttpClient _http = new HttpClient();
        private static readonly string[] _allowedHosts = { "api.example.com", "services.internal.local" };

        [HttpGet("fetch")]
        public IActionResult Fetch()
        {
            var url = Request.Query["url"].ToString();
            if (!Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                return BadRequest("Invalid URL");
            }

            var uri = new Uri(url);
            if (Array.IndexOf(_allowedHosts, uri.Host) < 0)
            {
                return BadRequest("Host not allowed");
            }

            var resp = _http.GetAsync(uri).Result;
            var body = resp.Content.ReadAsStringAsync().Result;
            return Ok(new { Body = body });
        }
    }
}
