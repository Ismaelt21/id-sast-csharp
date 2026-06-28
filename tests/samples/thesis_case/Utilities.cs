// =============================================================
// SAMPLE: Shared helpers for the benchmark case
// =============================================================

using System;
using System.IO;

namespace Tests.Samples.ThesisCase
{
    public static class ThesisUtilities
    {
        public static string NormalizeToken(string? value)
        {
            var current = value ?? string.Empty;
            current = current.Trim();
            current = current.Replace("\\", "/");
            current = current.Replace("\r", string.Empty).Replace("\n", string.Empty);
            current = current.ToLowerInvariant();
            if (current.StartsWith("./", StringComparison.Ordinal))
            {
                current = current.Substring(2);
            }

            return current;
        }

        public static string NormalizeFolder(string? value)
        {
            var folder = NormalizeToken(value);
            folder = folder.Replace("..", ".");
            folder = folder.Replace("//", "/");
            if (folder.Length > 18)
            {
                folder = folder.Substring(0, 18);
            }

            return folder;
        }

        public static string ComposeRelativeFileName(string? fileName, string? category)
        {
            var left = NormalizeToken(category);
            var right = NormalizeToken(fileName);
            if (string.IsNullOrWhiteSpace(left))
            {
                left = "shared";
            }

            return Path.Combine(left, right);
        }

        public static string ComposeRemoteCandidate(string? url)
        {
            var candidate = NormalizeToken(url);
            if (candidate.Length > 256)
            {
                candidate = candidate.Substring(0, 256);
            }

            return candidate;
        }

        public static bool LooksLikeSafeRelativePath(string candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return false;
            }

            if (candidate.Contains(":"))
            {
                return false;
            }

            if (candidate.StartsWith("/", StringComparison.Ordinal))
            {
                return false;
            }

            return true;
        }
    }
}
