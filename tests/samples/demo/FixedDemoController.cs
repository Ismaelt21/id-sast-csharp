// =============================================================
//tests/samples/demo/FixedDemoController.cs
// SAMPLE: Ecommerce demo fixed version
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL
// SEVERITY: CRITICAL
// CWE: CWE-89, CWE-22
// SOURCE: HttpRequest.Query["id"], IFormFile.FileName
// SINK: System.Data.SqlClient.SqlCommand..ctor, System.IO.File.ReadAllText
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Corrige SQLi usando parámetros y corrige path traversal normalizando el nombre y validando el path
// =============================================================

using Microsoft.Data.SqlClient;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Demo
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedDemoController : ControllerBase
    {
        private readonly string _invoicesDir = Path.GetFullPath("invoices");

        [HttpGet("product")]
        public IActionResult GetProduct()
        {
            var id = Request.Query["id"].ToString();
            using var conn = new SqlConnection("Server=.;Database=Shop;Trusted_Connection=True;");
            using var cmd = new SqlCommand("SELECT Id, Name, Price FROM Products WHERE Id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            conn.Open();
            using var rdr = cmd.ExecuteReader();
            if (rdr.Read()) return Ok(new { Id = rdr[0], Name = rdr[1], Price = rdr[2] });
            return NotFound();
        }

        [HttpPost("invoice")]
        public IActionResult GetInvoice(IFormFile file)
        {
            if (file == null) return BadRequest();
            var filename = Path.GetFileName(file.FileName);
            var candidate = Path.GetFullPath(Path.Combine(_invoicesDir, filename));
            if (!candidate.StartsWith(_invoicesDir)) return BadRequest("Invalid file path");
            if (!System.IO.File.Exists(candidate)) return NotFound();
            var content = System.IO.File.ReadAllText(candidate);
            return File(System.Text.Encoding.UTF8.GetBytes(content), "application/pdf", filename);
        }
    }
}
