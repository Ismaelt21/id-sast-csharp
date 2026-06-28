// =============================================================
// SAMPLE: Main benchmark controller for thesis evaluation
// VULNERABILITY: SQL_INJECTION, PATH_TRAVERSAL, SSRF
// FRAMEWORK: aspnetcore
// =============================================================

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

        public VulnerableThesisController()
        {
            _orderService = new OrderService("Server=.;Database=ThesisShop;Trusted_Connection=True;");
            _fileService = new FileService("documents");
            _remoteFetchService = new RemoteFetchService(new HttpClient());
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
    }
}
