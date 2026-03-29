using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Infrastructure.Metrics
{
    public class FileMetricsRepository : IMetricsRepository
    {
        private readonly string _filePath;
        private static readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

        public FileMetricsRepository()
        {
            _filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "waf_performance_metrics.csv");

            if (!File.Exists(_filePath))
            {
                File.WriteAllText(_filePath, "Timestamp,Method,ExecutionTimeMs,WasAttackDetected,AttackType\n");
            }
        }

        public async Task SaveAsync(PerformanceMetrics metrics)
        {
            // Formatowanie czasu, żeby Excel/Python łatwo zinterpretował ułamki z kropką
            string timeString = metrics.ExecutionTimeMs.ToString(System.Globalization.CultureInfo.InvariantCulture);
            string timestampStr = metrics.Timestamp.ToString("O");

            string csvLine = $"{timestampStr},{metrics.DetectionMethod},{timeString},{metrics.IsAttack},{metrics.AttackType}\n";

            await _semaphore.WaitAsync();
            try
            {
                await File.AppendAllTextAsync(_filePath, csvLine);
            }
            finally
            {
                _semaphore.Release();
            }
        }
    }
}
