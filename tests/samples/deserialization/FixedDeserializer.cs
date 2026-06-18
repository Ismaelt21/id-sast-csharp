// =============================================================
// SAMPLE: Insecure Deserialization via BinaryFormatter
// VULNERABILITY: INSECURE_DESERIALIZATION
// SEVERITY: CRITICAL
// CWE: CWE-502
// SOURCE: HttpRequest.Body
// SINK: System.Text.Json.JsonSerializer.Deserialize
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa System.Text.Json con tipo explícito y validación
// =============================================================

using System.IO;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Deserialization
{
    public class PayloadModel { public string Name { get; set; } }

    [ApiController]
    [Route("api/[controller]")]
    public class FixedDeserializer : ControllerBase
    {
        [HttpPost("data")]
        public IActionResult Data()
        {
            using var ms = new MemoryStream();
            Request.Body.CopyTo(ms);
            ms.Position = 0;

            // Fix: deserialize to known type using System.Text.Json
            var model = JsonSerializer.Deserialize<PayloadModel>(ms);
            if (model == null) return BadRequest();
            return Ok(new { model.Name });
        }
    }
}
