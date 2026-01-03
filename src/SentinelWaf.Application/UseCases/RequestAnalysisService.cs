using SentinelWaf.Application.Abstractions;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.UseCases
{
    public sealed class RequestAnalysisService : IRequestAnalysisService
    {
        private readonly IDetectionPipeline _pipeline;

        public RequestAnalysisService(IDetectionPipeline pipeline)
        {
            _pipeline = pipeline;
        }

        public Task<IReadOnlyList<ThreatDetectionResult>> AnalyzeAsync(
            HttpRequestData request,
            CancellationToken cancellationToken = default)
        {
            return _pipeline.ExecuteAsync(request, cancellationToken);
        }
    }
}
