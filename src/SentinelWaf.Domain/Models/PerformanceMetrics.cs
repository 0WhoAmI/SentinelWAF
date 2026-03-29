using SentinelWaf.Domain.Enums;

namespace SentinelWaf.Domain.Models
{
    public record PerformanceMetrics(
        DetectionMethod DetectionMethod,
        double ExecutionTimeMs,
        bool IsAttack,
        AttackType AttackType,
        DateTime Timestamp
    );
}
