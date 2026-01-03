using SentinelWaf.Domain.Enums;
using SentinelWaf.Infrastructure.Options;
using System.Text.RegularExpressions;

namespace SentinelWaf.Infrastructure.DetectionEngines.RegexEngine
{
    public static class RegexRules
    {
        public static IReadOnlyList<(Regex Regex, ThreatType Type)> GetRules(SensitivityLevel level)
        {
            var rules = new List<(Regex, ThreatType)>
            {
                // ===== SQL INJECTION =====
                (new Regex(@"(\%27)|(')|(\-\-)", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.SqlInjection),
                (new Regex(@"\bOR\b\s+\d=\d", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.SqlInjection),
                (new Regex(@"\bUNION\b.*\bSELECT\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.SqlInjection),

                // ===== XSS =====
                (new Regex(@"<script.*?>.*?</script>", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.Xss),
                (new Regex(@"onerror\s*=", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.Xss),
                (new Regex(@"javascript\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.Xss)
            };

            if (level >= SensitivityLevel.Medium)
            {
                rules.AddRange(new[]
                {
                    // ===== COMMAND INJECTION =====
                    (new Regex(@";\s*[a-zA-Z0-9_\-]+", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.CommandInjection),
                    (new Regex(@"\|\|\s*[a-zA-Z0-9_\-]+", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.CommandInjection),
                    
                    // ===== PATH TRAVERSAL =====
                    (new Regex(@"\.\./", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.PathTraversal)
                });
            }

            if (level == SensitivityLevel.High)
            {
                rules.AddRange(new[]
                {
                    // ===== ADVANCED SQLi =====
                    (new Regex(@"sleep\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.SqlInjection),
                    (new Regex(@"benchmark\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.SqlInjection),

                    // ===== COMMAND INJECTION =====
                    (new Regex(@"[;&|]{1,2}\s*\S+", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.CommandInjection),

                    // ===== ADVANCED PATH TRAVERSAL =====
                    (new Regex(@"/etc/passwd", RegexOptions.Compiled | RegexOptions.IgnoreCase), ThreatType.PathTraversal),
                });
            }

            return rules;
        }
    }
}
