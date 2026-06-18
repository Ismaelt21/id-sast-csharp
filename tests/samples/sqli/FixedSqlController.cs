// =============================================================
// SAMPLE: SQL Injection via QueryString
// VULNERABILITY: SQL_INJECTION
// SEVERITY: CRITICAL
// CWE: CWE-89
// SOURCE: HttpRequest.Query["id"]  
// SINK: System.Data.SqlClient.SqlCommand..ctor
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Uso de SqlParameter para evitar inyección SQL
// =============================================================

using Microsoft.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Sqli
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedSqlController : ControllerBase
    {
        [HttpGet("user")]
        public IActionResult GetUser()
        {
            var id = Request.Query["id"].ToString();

            using var conn = new SqlConnection("Server=.;Database=AppDb;Trusted_Connection=True;");
            using var cmd = new SqlCommand("SELECT Id, Name FROM Users WHERE Id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            conn.Open();
            using var rdr = cmd.ExecuteReader();
            if (rdr.Read())
                return Ok(new { Id = rdr[0], Name = rdr[1] });

            return NotFound();
        }
    }
}
