using SentinelWaf.Application.Abstractions;
using SentinelWaf.Domain.Abstractions;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.Pipelines
{
    public sealed class DetectionPipeline : IDetectionPipeline
    {
        private readonly IEnumerable<IThreatDetectionEngine> _engines;

        public DetectionPipeline(IEnumerable<IThreatDetectionEngine> engines)
        {
            _engines = engines;
        }

        public async Task<IReadOnlyList<ThreatDetectionResult>> ExecuteAsync(
            HttpRequestData request,
            CancellationToken cancellationToken = default)
        {
            var results = new List<ThreatDetectionResult>();

            foreach (var engine in _engines)
            {
                results.Add(await engine.AnalyzeAsync(request, cancellationToken));
            }

            return results;
        }
    }
}
