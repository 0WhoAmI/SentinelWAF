using SentinelWaf.Domain.Abstractions;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Options;
using SentinelWaf.Infrastructure.Telemetry;
using System.Diagnostics;

namespace SentinelWaf.Infrastructure.DetectionEngines.RegexEngine
{
    public sealed class RegexThreatDetectionEngine : IThreatDetectionEngine
    {
        private readonly RegexEngineOptions _options;
        private readonly MetricsCollector _metrics;

        public RegexThreatDetectionEngine(RegexEngineOptions options, MetricsCollector metrics)
        {
            _options = options;
            _metrics = metrics;
        }

        public string Name => "Regex";

        public ValueTask<ThreatDetectionResult> AnalyzeAsync(HttpRequestData request, CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();

            var rules = RegexRules.GetRules(_options.Sensitivity);

            foreach (var (regex, threatType) in rules)
            {
                if (regex.IsMatch(request.Path) || regex.IsMatch(request.Body ?? string.Empty))
                {
                    sw.Stop();
                    _metrics.Track($"{Name}_ExecutionTime", sw.Elapsed.TotalMilliseconds);
                    return new ValueTask<ThreatDetectionResult>(
                        new ThreatDetectionResult(true, threatType, Domain.Enums.DetectionConfidence.High, Name, sw.Elapsed)
                    );
                }
            }

            sw.Stop();
            _metrics.Track($"{Name}_ExecutionTime", sw.Elapsed.TotalMilliseconds);

            return new ValueTask<ThreatDetectionResult>(
                ThreatDetectionResult.NoThreat(Name, sw.Elapsed)
            );
        }
    }
}
