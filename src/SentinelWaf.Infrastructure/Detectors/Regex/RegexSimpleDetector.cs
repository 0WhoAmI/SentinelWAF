using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SystemRegex = System.Text.RegularExpressions;

namespace SentinelWaf.Infrastructure.Detectors.Regex
{
    public class RegexSimpleDetector : IAttackDetector
    {
        // RegexOptions.Compiled jest kluczowe przy testach wydajnościowych
        private static readonly SystemRegex.Regex _sqliRegex = new SystemRegex.Regex(@"(?i)(select|drop|union|insert|delete|update)", SystemRegex.RegexOptions.Compiled);
        private static readonly SystemRegex.Regex _xssRegex = new SystemRegex.Regex(@"(?i)<script>", SystemRegex.RegexOptions.Compiled);

        public InspectionResult Analyze(InspectionRequest request)
        {
            if (_sqliRegex.IsMatch(request.Body) || _sqliRegex.IsMatch(request.QueryString))
                return new InspectionResult(true, ThreatLevel.Low, AttackType.SqlInjection, DetectionMethod.RegexSimple);

            if (_xssRegex.IsMatch(request.Body) || _xssRegex.IsMatch(request.QueryString))
                return new InspectionResult(true, ThreatLevel.Low, AttackType.CrossSiteScripting, DetectionMethod.RegexSimple);

            return new InspectionResult(false, ThreatLevel.None, AttackType.None, DetectionMethod.RegexSimple);
        }
    }
}
