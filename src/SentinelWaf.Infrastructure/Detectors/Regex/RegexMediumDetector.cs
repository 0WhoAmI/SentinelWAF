using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SystemRegex = System.Text.RegularExpressions;

namespace SentinelWaf.Infrastructure.Detectors.Regex
{
    public class RegexMediumDetector : IAttackDetector
    {
        private static readonly System.Text.RegularExpressions.Regex _sqliRegex =
            new System.Text.RegularExpressions.Regex(
                @"(?i)(?:\b(select|update|insert|delete|drop)\b.*\b(from|into|table)\b)|(?:\bunion\b.*\bselect\b)|(?:[';]+\s*(?:--|\#|\/\*))",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        private static readonly System.Text.RegularExpressions.Regex _xssRegex =
            new System.Text.RegularExpressions.Regex(
                @"(?i)<(script|iframe|object|embed|svg).*?>|javascript:|on(load|error|mouseover|focus|click)\s*=",
                System.Text.RegularExpressions.RegexOptions.Compiled);

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
