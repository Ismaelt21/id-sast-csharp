// =============================================================
// SAMPLE: Insecure Deserialization via BinaryFormatter
// VULNERABILITY: INSECURE_DESERIALIZATION
// SEVERITY: CRITICAL
// CWE: CWE-502
// SOURCE: HttpRequest.Body
// SINK: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Deserializa directamente el stream del usuario con BinaryFormatter
// =============================================================

using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Deserialization
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableDeserializer : ControllerBase
    {
        [HttpPost("data")]
        public IActionResult Data()
        {
            using var ms = new MemoryStream();
            Request.Body.CopyTo(ms);
            ms.Position = 0;

            var bf = new BinaryFormatter();
            // Vulnerable: unsafe deserialization of user-provided binary
            var obj = bf.Deserialize(ms);
            return Ok(new { Type = obj?.GetType().FullName });
        }
    }
}
