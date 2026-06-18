// =============================================================
//tests/samples/demo/VulnerableDemoController.cs
// SAMPLE: Ecommerce demo with SQLi + Path Traversal
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL
// SEVERITY: CRITICAL
// CWE: CWE-89, CWE-22
// SOURCE: HttpRequest.Query["id"], IFormFile.FileName
// SINK: System.Data.SqlClient.SqlCommand..ctor, System.IO.File.ReadAllText
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Endpoints que muestran un patrón realista: búsqueda de producto vulnerable a SQLi y descarga de factura vulnerable a path traversal
// =============================================================

using Microsoft.Data.SqlClient;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Demo
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableDemoController : ControllerBase
    {
        // Vulnerable: SQL built by concatenating user input
        [HttpGet("product")]
        public IActionResult GetProduct()
        {
            var id = Request.Query["id"].ToString();
            var sql = "SELECT Id, Name, Price FROM Products WHERE Id = '" + id + "'";
            using var conn = new SqlConnection("Server=.;Database=Shop;Trusted_Connection=True;");
            using var cmd = new SqlCommand(sql, conn);
            conn.Open();
            using var rdr = cmd.ExecuteReader();
            if (rdr.Read()) return Ok(new { Id = rdr[0], Name = rdr[1], Price = rdr[2] });
            return NotFound();
        }

        // Vulnerable: use untrusted file name to read files
        [HttpPost("invoice")]
        public IActionResult GetInvoice(IFormFile file)
        {
            if (file == null) return BadRequest();
            var path = Path.Combine("invoices", file.FileName);
            if (!System.IO.File.Exists(path)) return NotFound();
            var content = System.IO.File.ReadAllText(path);
            return File(System.Text.Encoding.UTF8.GetBytes(content), "application/pdf", file.FileName);
        }
    }
}
