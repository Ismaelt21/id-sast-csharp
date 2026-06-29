// =============================================================
// SAMPLE: Shared helpers for the benchmark case
// =============================================================

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.Html;

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

        public static string NormalizeRedirectTarget(string? value)
        {
            var target = NormalizeToken(value);
            if (string.IsNullOrWhiteSpace(target))
            {
                target = "/dashboard";
            }

            if (!target.StartsWith("/", StringComparison.Ordinal) &&
                !target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                target = "/" + target;
            }

            return target;
        }

        public static string NormalizeCommandTarget(string? value)
        {
            var target = NormalizeToken(value);
            target = target.Replace("\"", string.Empty);
            if (target.Length > 64)
            {
                target = target.Substring(0, 64);
            }

            return target;
        }

        public static string NormalizePreviewText(string? value)
        {
            var text = value ?? string.Empty;
            text = text.Trim();
            text = text.Replace("\r", " ");
            text = text.Replace("\n", " ");
            if (text.Length > 140)
            {
                text = text.Substring(0, 140);
            }

            return text;
        }

        public static string NormalizeXmlPayload(string? value)
        {
            var xml = value ?? string.Empty;
            xml = xml.Trim();
            xml = xml.Replace("\0", string.Empty);
            if (xml.Length > 8192)
            {
                xml = xml.Substring(0, 8192);
            }

            return xml;
        }
    }

    public sealed class ThesisNavigationService
    {
        public RedirectResultDto ResolveRedirect(RedirectRequestDto request)
        {
            var target = PrepareTarget(request);
            return new RedirectResultDto
            {
                Url = target,
                Source = request.Source
            };
        }

        private string PrepareTarget(RedirectRequestDto request)
        {
            var target = ThesisUtilities.NormalizeRedirectTarget(request.ReturnUrl);
            if (!string.IsNullOrWhiteSpace(request.Campaign))
            {
                var campaign = request.Campaign.Trim();
                if (campaign.Length > 24)
                {
                    campaign = campaign.Substring(0, 24);
                }

                if (target.Contains("?", StringComparison.Ordinal))
                {
                    target = target + "&campaign=" + campaign;
                }
                else
                {
                    target = target + "?campaign=" + campaign;
                }
            }

            return target;
        }
    }

    public sealed class ThesisCommandService
    {
        public CommandProbeResultDto RunProbe(CommandProbeRequestDto request)
        {
            var command = BuildCommand(request);
            var output = Execute(command);
            return new CommandProbeResultDto
            {
                Command = command,
                ExitCode = output.exitCode,
                Output = output.text
            };
        }

        private string BuildCommand(CommandProbeRequestDto request)
        {
            var host = ThesisUtilities.NormalizeCommandTarget(request.TargetHost);
            var mode = ThesisUtilities.NormalizeToken(request.Mode);
            var command = "ping -n 1 " + host;

            if (mode == "trace")
            {
                command = command + " && tracert " + host;
            }

            if (!string.IsNullOrWhiteSpace(request.CorrelationId))
            {
                var cid = request.CorrelationId.Trim();
                command = command + " && echo " + cid;
            }

            return command;
        }

        private static (int exitCode, string text) Execute(string command)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + command,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                return (-1, string.Empty);
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, stdout + stderr);
        }
    }

    public sealed class ThesisPreviewService
    {
        public PreviewResultDto BuildPreview(PreviewRequestDto request)
        {
            var title = ThesisUtilities.NormalizePreviewText(request.Text);
            var highlight = ThesisUtilities.NormalizePreviewText(request.Highlight);
            var theme = string.IsNullOrWhiteSpace(request.Theme) ? "default" : request.Theme.Trim().ToLowerInvariant();

            var html = new HtmlString(
                "<section class=\"preview preview-" + theme + "\">" +
                "<header><h2>" + title + "</h2></header>" +
                "<p>" + highlight + "</p>" +
                "</section>");

            return new PreviewResultDto
            {
                Html = html.ToString(),
                Theme = theme
            };
        }
    }

    public sealed class ThesisXmlImportService
    {
        public XmlImportResultDto Import(string payload, string? ticketId)
        {
            payload = ThesisUtilities.NormalizeXmlPayload(payload);
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(payload));
            var document = System.Xml.Linq.XDocument.Load(stream);

            return new XmlImportResultDto
            {
                RootElement = document.Root?.Name.LocalName ?? string.Empty,
                NamespaceUri = document.Root?.Name.NamespaceName ?? string.Empty,
                TicketId = ticketId ?? string.Empty
            };
        }
    }
}
