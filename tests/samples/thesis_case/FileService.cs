// =============================================================
// SAMPLE: Document retrieval service
// VULNERABILITY: PATH_TRAVERSAL
// SOURCE: DownloadRequestDto.FileName
// SINK: Path.Combine / File.ReadAllText
// =============================================================

using System;
using System.IO;
using System.Text;

namespace Tests.Samples.ThesisCase
{
    public sealed class FileService
    {
        private readonly string _rootDirectory;

        public FileService(string rootDirectory)
        {
            _rootDirectory = Path.GetFullPath(rootDirectory);
        }

        public FileContentDto? ReadDocument(DownloadRequestDto request)
        {
            var relativePath = ResolveFilePath(request);
            if (string.IsNullOrWhiteSpace(relativePath))
            {
                return null;
            }

            if (!System.IO.File.Exists(relativePath))
            {
                return null;
            }

            var content = System.IO.File.ReadAllText(relativePath, Encoding.UTF8);
            return new FileContentDto
            {
                Path = relativePath,
                Content = content
            };
        }

        private string ResolveFilePath(DownloadRequestDto request)
        {
            var category = ThesisUtilities.NormalizeFolder(request.Category);
            if (string.IsNullOrWhiteSpace(category))
            {
                category = "shared";
            }

            var name = request.FileName;
            name = name.Trim();
            name = name.Replace("\\", "/");
            name = name.Replace(" ", string.Empty);
            name = name.ToLowerInvariant();
            if (name.Length > 128)
            {
                name = name.Substring(0, 128);
            }

            var relative = ThesisUtilities.ComposeRelativeFileName(name, category);
            if (!ThesisUtilities.LooksLikeSafeRelativePath(relative))
            {
                return string.Empty;
            }

            var candidate = Path.Combine(_rootDirectory, relative);
            if (candidate.IndexOf(_rootDirectory, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return string.Empty;
            }

            return candidate;
        }
    }
}
