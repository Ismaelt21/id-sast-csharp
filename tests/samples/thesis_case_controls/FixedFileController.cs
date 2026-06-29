// =============================================================
// SAMPLE: Path Traversal control case
// VULNERABILITY: PATH_TRAVERSAL
// SEVERITY: HIGH
// CWE: CWE-22
// SOURCE: HttpRequest.Query["file"]
// SINK: System.IO.File.ReadAllText
// EXPECTED_FINDING: false
// FRAMEWORK: aspnetcore
// DESCRIPTION: Normaliza el nombre y valida que permanezca dentro del directorio base
// =============================================================

using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class FixedFileController : ControllerBase
    {
        private readonly string _baseDirectory = Path.GetFullPath("uploads");

        [HttpGet("read")]
        public IActionResult Read()
        {
            var folder = Request.Query["folder"].ToString();
            var file = Request.Query["file"].ToString();
            var safeFolder = string.IsNullOrWhiteSpace(folder) ? "shared" : Path.GetFileName(folder.Trim());
            var safeFile = Path.GetFileName(file.Trim());
            var candidate = Path.GetFullPath(Path.Combine(_baseDirectory, safeFolder, safeFile));

            if (!candidate.StartsWith(_baseDirectory))
            {
                return BadRequest("Invalid path");
            }

            if (!System.IO.File.Exists(candidate))
            {
                return NotFound();
            }

            var content = System.IO.File.ReadAllText(candidate);
            return Ok(new { Content = content });
        }
    }
}
