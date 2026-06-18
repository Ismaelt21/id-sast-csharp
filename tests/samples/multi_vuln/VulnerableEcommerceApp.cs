// =============================================================
// SAMPLE: Multiple vulnerabilities in an ecommerce controller
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL, OPEN_REDIRECT, LOG_INJECTION
// SEVERITY: CRITICAL
// CWE: CWE-89, CWE-22, CWE-601, CWE-117
// SOURCE: HttpRequest.Query / IFormFile.FileName
// SINK: SqlCommand, File.ReadAllText, Redirect, ILogger.LogInformation
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Controller simula endpoints de búsqueda, descarga, login y registro con vulnerabilidades realesistas
// =============================================================

using System.Data.SqlClient;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Tests.Samples.MultiVuln
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableEcommerceApp : ControllerBase
    {
        private readonly ILogger<VulnerableEcommerceApp> _logger;

        public VulnerableEcommerceApp(ILogger<VulnerableEcommerceApp> logger)
        {
            _logger = logger;
        }

        // 1) SQL Injection in product search
        [HttpGet("search")]
        public IActionResult Search()
        {
            var q = Request.Query["q"].ToString();
            var sql = "SELECT Id, Name FROM Products WHERE Name LIKE '%" + q + "%'";
            using var conn = new SqlConnection("Server=.;Database=Shop;Trusted_Connection=True;");
            using var cmd = new SqlCommand(sql, conn);
            conn.Open();
            using var rdr = cmd.ExecuteReader();
            return Ok("results");
        }

        // 2) Path traversal in invoice download
        [HttpGet("invoice")]
        public IActionResult DownloadInvoice()
        {
            var fname = Request.Query["file"].ToString();
            var path = Path.Combine("invoices", fname);
            if (!System.IO.File.Exists(path)) return NotFound();
            var content = System.IO.File.ReadAllText(path);
            return File(System.Text.Encoding.UTF8.GetBytes(content), "application/pdf", fname);
        }

        // 3) Open redirect after login
        [HttpPost("login")]
        public IActionResult Login()
        {
            var returnUrl = Request.Query["returnUrl"].ToString();
            // Vulnerable: blindly redirect
            return Redirect(returnUrl);
        }

        // 4) Log injection on error registration
        [HttpPost("report")]
        public IActionResult Report()
        {
            var msg = Request.Query["msg"].ToString();
            _logger.LogInformation("User report: " + msg);
            return Ok();
        }
    }
}
