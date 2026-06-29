// =============================================================
// SAMPLE: Thesis benchmark case for a realistic service portal
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL, SSRF, OPEN_REDIRECT, COMMAND_INJECTION, XSS, XXE
// SEVERITY: CRITICAL / HIGH / MEDIUM
// FRAMEWORK: aspnetcore
// DESCRIPTION: Domain models and DTOs used by the benchmark sample
// =============================================================

namespace Tests.Samples.ThesisCase
{
    public sealed class OrderRequestDto
    {
        public string OrderId { get; set; } = string.Empty;
        public string CustomerSegment { get; set; } = string.Empty;
        public string? CorrelationId { get; set; }
    }

    public sealed class DownloadRequestDto
    {
        public string FileName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string? Tenant { get; set; }
    }

    public sealed class RemoteFetchRequestDto
    {
        public string Url { get; set; } = string.Empty;
        public string Channel { get; set; } = string.Empty;
        public string? Region { get; set; }
    }

    public sealed class RedirectRequestDto
    {
        public string ReturnUrl { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string? Campaign { get; set; }
    }

    public sealed class CommandProbeRequestDto
    {
        public string TargetHost { get; set; } = string.Empty;
        public string Mode { get; set; } = string.Empty;
        public string? CorrelationId { get; set; }
    }

    public sealed class PreviewRequestDto
    {
        public string Text { get; set; } = string.Empty;
        public string Theme { get; set; } = string.Empty;
        public string? Highlight { get; set; }
    }

    public sealed class XmlImportRequestDto
    {
        public string PayloadXml { get; set; } = string.Empty;
        public string SourceSystem { get; set; } = string.Empty;
        public string? TicketId { get; set; }
    }

    public sealed class OrderSummaryDto
    {
        public string OrderNumber { get; set; } = string.Empty;
        public string CustomerName { get; set; } = string.Empty;
        public decimal TotalAmount { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public sealed class FileContentDto
    {
        public string Path { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
    }

    public sealed class RemotePayloadDto
    {
        public string Source { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
    }

    public sealed class RedirectResultDto
    {
        public string Url { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
    }

    public sealed class CommandProbeResultDto
    {
        public string Command { get; set; } = string.Empty;
        public int ExitCode { get; set; }
        public string Output { get; set; } = string.Empty;
    }

    public sealed class PreviewResultDto
    {
        public string Html { get; set; } = string.Empty;
        public string Theme { get; set; } = string.Empty;
    }

    public sealed class XmlImportResultDto
    {
        public string RootElement { get; set; } = string.Empty;
        public string NamespaceUri { get; set; } = string.Empty;
        public string TicketId { get; set; } = string.Empty;
    }
}
