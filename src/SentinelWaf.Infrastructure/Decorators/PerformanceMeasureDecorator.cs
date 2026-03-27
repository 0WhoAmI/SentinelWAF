using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Models;
using System.Diagnostics;

namespace SentinelWaf.Infrastructure.Decorators
{
    // WZORZEC DEKORATOR: Opakowuje dowolny IAttackDetector i dodaje pomiar czasu.
    public class PerformanceMeasureDecorator : IAttackDetector
    {
        private readonly IAttackDetector _innerDetector;
        private readonly IMetricsRepository _metricsRepository;

        public PerformanceMeasureDecorator(
            IAttackDetector innerDetector,
            IMetricsRepository metricsRepository)
        {
            _innerDetector = innerDetector;
            _metricsRepository = metricsRepository;
        }

        public InspectionResult Analyze(InspectionRequest request)
        {
            var stopwatch = Stopwatch.StartNew();

            // Wywołanie właściwego detektora (np. RegexMedium)
            InspectionResult result = _innerDetector.Analyze(request);

            stopwatch.Stop();

            // Zapisanie wyników
            PerformanceMetrics metrics = new PerformanceMetrics(
                result.Method,
                stopwatch.ElapsedMilliseconds,
                result.IsAttack,
                DateTime.UtcNow);

            _metricsRepository.Save(metrics);

            return result;
        }
    }
}
