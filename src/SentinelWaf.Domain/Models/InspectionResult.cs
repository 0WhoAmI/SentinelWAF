using SentinelWaf.Domain.Enums;

namespace SentinelWaf.Domain.Models
{
    public record InspectionResult(
        bool IsAttack,
        ThreatLevel Level,
        AttackType Type,
        DetectionMethod Method
    );
}
