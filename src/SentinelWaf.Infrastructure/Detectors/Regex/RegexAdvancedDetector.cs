using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SystemRegex = System.Text.RegularExpressions;

namespace SentinelWaf.Infrastructure.Detectors.Regex
{
    public class RegexAdvancedDetector : IAttackDetector
    {
        // Ustawiamy limit czasu (Timeout) - przy tak skomplikowanych Regexach haker może użyć 
        // ataku ReDoS (Regular Expression Denial of Service), żeby zawiesić serwer!
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(500);
        private static readonly SystemRegex.Regex _sqliRegex = new SystemRegex.Regex(@"(?i)(?:['""]|%22|%27|%60|%2527)\s*(?:and|or|\|\||&&)\s*(?:['""]|%22|%27|%60|%2527)?\s*\d+\s*(?:=|=>|<=|<|>)\s*(?:['""]|%22|%27|%60|%2527)?\s*\d+|(?:\b(?:union\s+all\s+select|waitfor\s+delay|xp_cmdshell)\b)", SystemRegex.RegexOptions.Compiled, RegexTimeout);
        private static readonly SystemRegex.Regex _xssRegex = new SystemRegex.Regex(@"(?i)(?:<|[<]\s*)(?:script|object|embed|iframe|svg|math|marquee)(?:\s+|[^\w>]*)(?:.*?\s+)?(?:on[a-z]+|xmlns)\s*=\s*(?:['""]?[^>]*['""]?|[^>]*)(?:>|[>]\s*)", SystemRegex.RegexOptions.Compiled, RegexTimeout);

        public InspectionResult Analyze(InspectionRequest request)
        {
            try
            {
                if (_sqliRegex.IsMatch(request.Body) || _sqliRegex.IsMatch(request.QueryString))
                    return new InspectionResult(true, ThreatLevel.High, AttackType.SqlInjection, DetectionMethod.RegexAdvanced);

                if (_xssRegex.IsMatch(request.Body) || _xssRegex.IsMatch(request.QueryString))
                    return new InspectionResult(true, ThreatLevel.High, AttackType.CrossSiteScripting, DetectionMethod.RegexAdvanced);
            }
            catch (SystemRegex.RegexMatchTimeoutException)
            {
                // Regex się "zakrztusił" 
                return new InspectionResult(true, ThreatLevel.High, AttackType.AnomalyUnknown, DetectionMethod.RegexAdvanced);
            }

            return new InspectionResult(false, ThreatLevel.None, AttackType.None, DetectionMethod.RegexAdvanced);
        }
    }
}
