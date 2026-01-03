using SentinelWaf.Domain.Abstractions;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Infrastructure.DetectionEngines.MachineLearningEngine
{
    public sealed class MlThreatDetectionEngine : IThreatDetectionEngine
    {
        public string Name => "ML";

        public ValueTask<ThreatDetectionResult> AnalyzeAsync(
            HttpRequestData request,
            CancellationToken cancellationToken = default)
        {
            return new ValueTask<ThreatDetectionResult>(
                ThreatDetectionResult.NoThreat(Name, TimeSpan.Zero)
            );
        }
    }
}
