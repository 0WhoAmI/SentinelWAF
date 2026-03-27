using SentinelWaf.Domain.Enums;

namespace SentinelWaf.Domain.Models
{
    public record PerformanceMetrics(
        DetectionMethod Method,
        long ExecutionTimeMs,
        bool WasAttackDetected,
        DateTime Timestamp
    );
}
