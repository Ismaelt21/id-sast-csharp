// =============================================================
// SAMPLE: Main benchmark controller for thesis evaluation
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL, SSRF, OPEN_REDIRECT, COMMAND_INJECTION, XSS, XXE
// FRAMEWORK: aspnetcore
// =============================================================

using System.IO;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace Tests.Samples.ThesisCase
{
    [ApiController]
    [Route("api/thesis")]
    public class VulnerableThesisController : ControllerBase
    {
        private readonly OrderService _orderService;
        private readonly FileService _fileService;
        private readonly RemoteFetchService _remoteFetchService;
        private readonly ThesisNavigationService _navigationService;
        private readonly ThesisCommandService _commandService;
        private readonly ThesisPreviewService _previewService;
        private readonly ThesisXmlImportService _xmlImportService;

        public VulnerableThesisController()
        {
            _orderService = new OrderService("Server=.;Database=ThesisShop;Trusted_Connection=True;");
            _fileService = new FileService("documents");
            _remoteFetchService = new RemoteFetchService(new HttpClient());
            _navigationService = new ThesisNavigationService();
            _commandService = new ThesisCommandService();
            _previewService = new ThesisPreviewService();
            _xmlImportService = new ThesisXmlImportService();
        }

        [HttpGet("order")]
        public IActionResult GetOrder()
        {
            var request = BuildOrderRequest();
            var result = _orderService.LoadOrder(request);
            if (result == null)
            {
                return NotFound();
            }

            return Ok(result);
        }

        [HttpGet("download")]
        public IActionResult Download()
        {
            var request = BuildDownloadRequest();
            var result = _fileService.ReadDocument(request);
            if (result == null)
            {
                return NotFound();
            }

            return Ok(result);
        }

        [HttpGet("fetch")]
        public IActionResult Fetch()
        {
            var request = BuildRemoteFetchRequest();
            var result = _remoteFetchService.FetchPartnerContent(request);
            if (result == null)
            {
                return BadRequest();
            }

            return Ok(result);
        }

        [HttpGet("redirect")]
        public IActionResult RedirectUser()
        {
            var request = BuildRedirectRequest();
            var returnUrl = Request.Query["returnUrl"].ToString();
            var result = _navigationService.ResolveRedirect(request);
            var target = string.IsNullOrWhiteSpace(returnUrl) ? result.Url : returnUrl;
            return Redirect(target);
        }

        [HttpGet("probe")]
        public IActionResult Probe()
        {
            var request = BuildCommandProbeRequest();
            var result = _commandService.RunProbe(request);
            return Ok(result);
        }

        [HttpGet("preview")]
        public IActionResult Preview()
        {
            var request = BuildPreviewRequest();
            var result = _previewService.BuildPreview(request);
            return new ContentResult
            {
                Content = result.Html,
                ContentType = "text/html",
                StatusCode = 200
            };
        }

        [HttpPost("import")]
        [ValidateAntiForgeryToken]
        public IActionResult ImportXml()
        {
            var payload = ReadRequestBody();
            var request = BuildXmlImportRequest();
            var result = _xmlImportService.Import(payload, request.TicketId);
            return Ok(result);
        }

        private OrderRequestDto BuildOrderRequest()
        {
            var rawId = Request.Query["id"].ToString();
            var segment = Request.Query["segment"].ToString();
            var correlation = Request.Query["cid"].ToString();
            if (string.IsNullOrWhiteSpace(segment))
            {
                segment = "retail";
            }

            return new OrderRequestDto
            {
                OrderId = rawId,
                CustomerSegment = segment,
                CorrelationId = string.IsNullOrWhiteSpace(correlation) ? null : correlation
            };
        }

        private DownloadRequestDto BuildDownloadRequest()
        {
            var file = Request.Query["file"].ToString();
            var category = Request.Query["category"].ToString();
            var tenant = Request.Query["tenant"].ToString();

            return new DownloadRequestDto
            {
                FileName = file,
                Category = string.IsNullOrWhiteSpace(category) ? "invoices" : category,
                Tenant = string.IsNullOrWhiteSpace(tenant) ? null : tenant
            };
        }

        private RemoteFetchRequestDto BuildRemoteFetchRequest()
        {
            var url = Request.Query["url"].ToString();
            var region = Request.Query["region"].ToString();
            var channel = Request.Query["channel"].ToString();
            if (string.IsNullOrWhiteSpace(channel))
            {
                channel = "sync";
            }

            return new RemoteFetchRequestDto
            {
                Url = url,
                Region = string.IsNullOrWhiteSpace(region) ? null : region,
                Channel = channel
            };
        }

        private RedirectRequestDto BuildRedirectRequest()
        {
            var returnUrl = Request.Query["returnUrl"].ToString();
            var source = Request.Query["source"].ToString();
            var campaign = Request.Query["campaign"].ToString();

            return new RedirectRequestDto
            {
                ReturnUrl = returnUrl,
                Source = string.IsNullOrWhiteSpace(source) ? "login" : source,
                Campaign = string.IsNullOrWhiteSpace(campaign) ? null : campaign
            };
        }

        private CommandProbeRequestDto BuildCommandProbeRequest()
        {
            var host = Request.Query["host"].ToString();
            var mode = Request.Query["mode"].ToString();
            var cid = Request.Query["cid"].ToString();

            return new CommandProbeRequestDto
            {
                TargetHost = host,
                Mode = string.IsNullOrWhiteSpace(mode) ? "ping" : mode,
                CorrelationId = string.IsNullOrWhiteSpace(cid) ? null : cid
            };
        }

        private PreviewRequestDto BuildPreviewRequest()
        {
            var text = Request.Query["text"].ToString();
            var theme = Request.Query["theme"].ToString();
            var highlight = Request.Query["highlight"].ToString();

            return new PreviewRequestDto
            {
                Text = text,
                Theme = string.IsNullOrWhiteSpace(theme) ? "default" : theme,
                Highlight = string.IsNullOrWhiteSpace(highlight) ? null : highlight
            };
        }

        private XmlImportRequestDto BuildXmlImportRequest()
        {
            var sourceSystem = Request.Query["sourceSystem"].ToString();
            var ticketId = Request.Query["ticketId"].ToString();

            return new XmlImportRequestDto
            {
                SourceSystem = string.IsNullOrWhiteSpace(sourceSystem) ? "partner" : sourceSystem,
                TicketId = string.IsNullOrWhiteSpace(ticketId) ? null : ticketId
            };
        }

        private string ReadRequestBody()
        {
            using var stream = new MemoryStream();
            Request.Body.CopyTo(stream);
            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }
}
