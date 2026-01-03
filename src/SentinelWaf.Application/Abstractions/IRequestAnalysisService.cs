using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.Abstractions
{
    public interface IRequestAnalysisService
    {
        Task<IReadOnlyList<ThreatDetectionResult>> AnalyzeAsync(
            HttpRequestData request,
            CancellationToken cancellationToken = default);
    }
}
