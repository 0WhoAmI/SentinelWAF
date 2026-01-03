using SentinelWaf.Domain.Models;

namespace SentinelWaf.Domain.Abstractions
{
    public interface IThreatDetectionEngine
    {
        string Name { get; }

        ValueTask<ThreatDetectionResult> AnalyzeAsync(
            HttpRequestData request,
            CancellationToken cancellationToken = default);
    }
}
