using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Infrastructure.Detectors.Regex
{
    public class RegexSimpleDetector : IAttackDetector
    {
        public InspectionResult Analyze(InspectionRequest request)
        {
            // TODO:

            // Tutaj logika prostego Regexa (poziom 1)
            bool isAttack = request.Body.Contains("DROP TABLE"); // Zwykły przykład
            return new InspectionResult(isAttack, ThreatLevel.Low, AttackType.SqlInjection, DetectionMethod.RegexSimple);
        }
    }
}
