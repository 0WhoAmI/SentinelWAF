using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Infrastructure.Metrics
{
    public class FileMetricsRepository : IMetricsRepository
    {
        public void Save(PerformanceMetrics metrics)
        {
            // TODO:
            // Tutaj logika dopisywania wiersza do pliku CSV (np. File.AppendAllText)
        }
    }
}
