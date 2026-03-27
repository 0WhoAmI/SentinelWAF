using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.Interfaces
{
    public interface IMetricsRepository
    {
        void Save(PerformanceMetrics metrics);
    }
}
