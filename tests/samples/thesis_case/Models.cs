// =============================================================
// SAMPLE: Thesis benchmark case for a realistic service portal
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL, SSRF
// SEVERITY: HIGH / CRITICAL
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
}
