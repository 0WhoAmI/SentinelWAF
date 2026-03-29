using SentinelWaf.Domain.Enums;

namespace SentinelWaf.Domain.Models
{
    public record InspectionResult(
        bool IsAttack,
        ThreatLevel ThreatLevel,
        AttackType AttackType,
        DetectionMethod DetectionMethod
    );
}
