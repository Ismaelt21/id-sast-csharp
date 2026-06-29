// =============================================================
// SAMPLE: XXE control case
// VULNERABILITY: XXE
// SEVERITY: HIGH
// CWE: CWE-611
// SOURCE: HttpRequest.Body
// SINK: System.Xml.Linq.XDocument.Load
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Carga XML con DTD habilitado y resolver activo
// =============================================================

using System.IO;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableXmlParser : ControllerBase
    {
        [HttpPost("parse")]
        [ValidateAntiForgeryToken]
        public IActionResult Parse()
        {
            using var ms = new MemoryStream();
            Request.Body.CopyTo(ms);
            ms.Position = 0;

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };

            using var reader = XmlReader.Create(ms, settings);
            var doc = XDocument.Load(reader);
            return Ok(new { Root = doc.Root?.Name.LocalName });
        }
    }
}
