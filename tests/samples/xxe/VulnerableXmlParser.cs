// =============================================================
// SAMPLE: XXE via XmlDocument.Load
// VULNERABILITY: XXE
// SEVERITY: HIGH
// CWE: CWE-611
// SOURCE: HttpRequest.Body
// SINK: System.Xml.XmlDocument.Load
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Carga XML sin deshabilitar DTDs, permitiendo XXE
// =============================================================

using System.IO;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Xxe
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableXmlParser : ControllerBase
    {
        [HttpPost("parse")]
        public IActionResult Parse()
        {
            using var ms = new MemoryStream();
            Request.Body.CopyTo(ms);
            ms.Position = 0;

            var doc = new XmlDocument();
            // Vulnerable: DTD processing enabled by default
            doc.Load(ms);
            return Ok(new { Root = doc.DocumentElement?.Name });
        }
    }
}
