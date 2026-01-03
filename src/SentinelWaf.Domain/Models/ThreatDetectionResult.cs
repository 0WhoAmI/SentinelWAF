using SentinelWaf.Domain.Enums;

namespace SentinelWaf.Domain.Models
{
    /// <summary>
    /// Wynik analizy pojedynczego silnika detekcji.
    /// </summary>
    public sealed record ThreatDetectionResult(
        bool IsThreat,
        ThreatType ThreatType,
        DetectionConfidence Confidence,
        string EngineName,
        TimeSpan ExecutionTime
    )
    {
        public static ThreatDetectionResult NoThreat(
            string engineName,
            TimeSpan executionTime)
            => new(
                false,
                ThreatType.None,
                DetectionConfidence.Low,
                engineName,
                executionTime
            );
    }
}
