// =============================================================
// SAMPLE: SQL Injection via QueryString
// VULNERABILITY: SQL_INJECTION
// SEVERITY: CRITICAL
// CWE: CWE-89
// SOURCE: HttpRequest.Query["id"]  
// SINK: System.Data.SqlClient.SqlCommand..ctor
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: SqlCommand construido con concatenación de QueryString
// =============================================================

using Microsoft.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Sqli
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableSqlController : ControllerBase
    {
        [HttpGet("user")]
        public IActionResult GetUser()
        {
            var id = Request.Query["id"].ToString();

            // Vulnerable concatenation
            var sql = "SELECT Id, Name FROM Users WHERE Id = '" + id + "'";
            using var conn = new SqlConnection("Server=.;Database=AppDb;Trusted_Connection=True;");
            using var cmd = new SqlCommand(sql, conn);
            conn.Open();
            using var rdr = cmd.ExecuteReader();
            if (rdr.Read())
                return Ok(new { Id = rdr[0], Name = rdr[1] });

            return NotFound();
        }
    }
}
