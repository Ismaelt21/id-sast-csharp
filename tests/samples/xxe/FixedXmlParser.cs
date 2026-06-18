// =============================================================
// SAMPLE: XXE via XmlDocument.Load
// VULNERABILITY: XXE
// SEVERITY: HIGH
// CWE: CWE-611
// SOURCE: HttpRequest.Body
// SINK: System.Xml.XmlReader
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa XmlReaderSettings con DtdProcessing=Prohibit para evitar XXE
// =============================================================

using System.IO;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.Xxe
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedXmlParser : ControllerBase
    {
        [HttpPost("parse")]
        public IActionResult Parse()
        {
            using var ms = new MemoryStream();
            Request.Body.CopyTo(ms);
            ms.Position = 0;

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };

            ms.Position = 0;
            using var reader = XmlReader.Create(ms, settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return Ok(new { Root = doc.DocumentElement?.Name });
        }
    }
}
