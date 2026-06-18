// =============================================================
// SAMPLE: SSRF via HttpClient.GetAsync
// VULNERABILITY: SSRF
// SEVERITY: HIGH
// CWE: CWE-918
// SOURCE: HttpRequest.Query["url"]
// SINK: System.Net.Http.HttpClient.GetAsync
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Valida el host contra una whitelist y usa Uri.IsWellFormedUriString
// =============================================================

using System;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Ssrf
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedSsrfController : ControllerBase
    {
        private static readonly HttpClient _http = new HttpClient();
        private static readonly string[] _whitelist = new[] { "api.example.com", "api.trusted.local" };

        [HttpGet("fetch")]
        public IActionResult Fetch()
        {
            var url = Request.Query["url"].ToString();
            if (!Uri.IsWellFormedUriString(url, UriKind.Absolute)) return BadRequest("Invalid URL");

            var u = new Uri(url);
            if (Array.IndexOf(_whitelist, u.Host) < 0) return BadRequest("Host not allowed");

            var resp = _http.GetAsync(u).Result;
            var body = resp.Content.ReadAsStringAsync().Result;
            return Ok(new { Body = body });
        }
    }
}
