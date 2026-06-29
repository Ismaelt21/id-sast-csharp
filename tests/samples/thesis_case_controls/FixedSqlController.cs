// =============================================================
// SAMPLE: SQL Injection control case
// VULNERABILITY: SQL_INJECTION
// SEVERITY: CRITICAL
// CWE: CWE-89
// SOURCE: HttpRequest.Query["id"]
// SINK: Microsoft.Data.SqlClient.SqlCommand
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa parametros para evitar SQL Injection
// =============================================================

using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedSqlController : ControllerBase
    {
        [HttpGet("user")]
        public IActionResult GetUser()
        {
            var id = Request.Query["id"].ToString();
            var suffix = Request.Query["suffix"].ToString();
            if (string.IsNullOrWhiteSpace(suffix))
            {
                suffix = string.Empty;
            }

            var normalized = id + suffix;
            using var conn = new SqlConnection("Server=.;Database=ThesisControls;Trusted_Connection=True;");
            using var cmd = new SqlCommand("SELECT Id, Name, Email FROM Users WHERE Id = @id", conn);
            cmd.Parameters.AddWithValue("@id", normalized);
            conn.Open();
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                return NotFound();
            }

            return Ok(new { Id = reader[0], Name = reader[1], Email = reader[2] });
        }
    }
}
