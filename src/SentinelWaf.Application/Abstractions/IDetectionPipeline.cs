using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.Abstractions
{
    public interface IDetectionPipeline
    {
        Task<IReadOnlyList<ThreatDetectionResult>> ExecuteAsync(
            HttpRequestData request,
            CancellationToken cancellationToken = default);
    }
}
