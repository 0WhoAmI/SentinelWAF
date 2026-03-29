using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.Interfaces
{
    public interface IMetricsRepository
    {
        Task SaveAsync(PerformanceMetrics metrics);
    }
}
