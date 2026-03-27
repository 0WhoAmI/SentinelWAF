using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SystemRegex = System.Text.RegularExpressions;

namespace SentinelWaf.Infrastructure.Detectors.Regex
{
    public class RegexMediumDetector : IAttackDetector
    {
        private static readonly SystemRegex.Regex _sqliRegex = new SystemRegex.Regex(@"(?i)(?:\b(select|update|insert|delete|drop)\b\s+.*\b(from|into|table)\b)|(?:[';]+\s*--+)", SystemRegex.RegexOptions.Compiled);
        private static readonly SystemRegex.Regex _xssRegex = new SystemRegex.Regex(@"(?i)<(script|iframe|object|embed|svg).*?>|javascript:", SystemRegex.RegexOptions.Compiled);

        public InspectionResult Analyze(InspectionRequest request)
        {
            if (_sqliRegex.IsMatch(request.Body) || _sqliRegex.IsMatch(request.QueryString))
                return new InspectionResult(true, ThreatLevel.Medium, AttackType.SqlInjection, DetectionMethod.RegexMedium);

            if (_xssRegex.IsMatch(request.Body) || _xssRegex.IsMatch(request.QueryString))
                return new InspectionResult(true, ThreatLevel.Medium, AttackType.CrossSiteScripting, DetectionMethod.RegexMedium);

            return new InspectionResult(false, ThreatLevel.None, AttackType.None, DetectionMethod.RegexMedium);
        }
    }
}
