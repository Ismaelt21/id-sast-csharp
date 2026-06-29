// =============================================================
// SAMPLE: Path Traversal control case
// VULNERABILITY: PATH_TRAVERSAL
// SEVERITY: HIGH
// CWE: CWE-22
// SOURCE: HttpRequest.Query["file"]
// SINK: System.IO.File.ReadAllText
// EXPECTED_FINDING: true
// FRAMEWORK: aspnetcore
// DESCRIPTION: Lee un archivo usando una ruta controlada por el usuario
// =============================================================

using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Tests.Samples.ThesisCaseControls
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableFileController : ControllerBase
    {
        [HttpGet("read")]
        public IActionResult Read()
        {
            var folder = Request.Query["folder"].ToString();
            var file = Request.Query["file"].ToString();
            var path = Path.Combine(folder, file);

            if (!System.IO.File.Exists(path))
            {
                return NotFound();
            }

            var content = System.IO.File.ReadAllText(path);
            return Ok(new { Content = content });
        }
    }
}
