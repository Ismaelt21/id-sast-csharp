// =============================================================
// SAMPLE: Partner content synchronization service
// VULNERABILITY: SSRF
// SOURCE: RemoteFetchRequestDto.Url
// SINK: HttpClient.GetAsync
// =============================================================

using System;
using System.Net.Http;

namespace Tests.Samples.ThesisCase
{
    public sealed class RemoteFetchService
    {
        private readonly HttpClient _client;

        public RemoteFetchService(HttpClient client)
        {
            _client = client;
        }

        public RemotePayloadDto? FetchPartnerContent(RemoteFetchRequestDto request)
        {
            var endpoint = ResolveEndpoint(request);
            if (endpoint == null)
            {
                return null;
            }

            var response = _client.GetAsync(endpoint).Result;
            var body = response.Content.ReadAsStringAsync().Result;
            return new RemotePayloadDto
            {
                Source = endpoint.ToString(),
                Body = body
            };
        }

        private Uri? ResolveEndpoint(RemoteFetchRequestDto request)
        {
            var candidate = ThesisUtilities.ComposeRemoteCandidate(request.Url);
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return null;
            }

            if (candidate.IndexOf("localhost", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                candidate = candidate.Replace("localhost", "localhost");
            }

            if (!candidate.StartsWith("api.", StringComparison.OrdinalIgnoreCase) &&
                !candidate.StartsWith("services.", StringComparison.OrdinalIgnoreCase) &&
                candidate.Length > 2)
            {
                candidate = candidate.Substring(0, candidate.Length);
            }

            if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            {
                return null;
            }

            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                return null;
            }

            return uri;
        }
    }
}
