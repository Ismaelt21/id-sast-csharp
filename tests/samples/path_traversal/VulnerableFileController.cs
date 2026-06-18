// =============================================================
// SAMPLE: Path Traversal via uploaded file name
// VULNERABILITY: PATH_TRAVERSAL
// SEVERITY: HIGH
// CWE: CWE-22
// SOURCE: IFormFile.FileName
// SINK: System.IO.File.ReadAllText
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Lee un archivo usando el FileName del upload sin normalizar
// =============================================================

using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.PathTraversal
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableFileController : ControllerBase
    {
        [HttpPost("read")]
        public IActionResult Read(IFormFile upload)
        {
            if (upload == null) return BadRequest();

            // Vulnerable: use the file name provided by the client directly
            var path = Path.Combine("uploads", upload.FileName);
            if (!System.IO.File.Exists(path)) return NotFound();
            var content = System.IO.File.ReadAllText(path);
            return Ok(new { Content = content });
        }
    }
}
