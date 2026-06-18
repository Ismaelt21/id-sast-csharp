// =============================================================
// SAMPLE: Path Traversal via uploaded file name
// VULNERABILITY: PATH_TRAVERSAL
// SEVERITY: HIGH
// CWE: CWE-22
// SOURCE: IFormFile.FileName
// SINK: System.IO.File.ReadAllText
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Usa Path.GetFileName y valida que el path final esté dentro de un directorio raíz
// =============================================================

using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.PathTraversal
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedFileController : ControllerBase
    {
        private readonly string _baseDir = Path.GetFullPath("uploads");

        [HttpPost("read")]
        public IActionResult Read(IFormFile upload)
        {
            if (upload == null) return BadRequest();

            var filename = Path.GetFileName(upload.FileName);
            var candidate = Path.GetFullPath(Path.Combine(_baseDir, filename));

            // Ensure that candidate is within base directory
            if (!candidate.StartsWith(_baseDir)) return BadRequest("Invalid file path");
            if (!System.IO.File.Exists(candidate)) return NotFound();
            var content = System.IO.File.ReadAllText(candidate);
            return Ok(new { Content = content });
        }
    }
}
