using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.DetectionEngines.RegexEngine;
using SentinelWaf.Infrastructure.Options;
using SentinelWaf.Infrastructure.Telemetry;
using System.IO;

namespace SentinelWaf.Tests.Infrastructure
{
    public class RegexThreatDetectionEngineTests
    {
        private MetricsCollector _metrics = new MetricsCollector();

        [Theory]
        [InlineData("/test")]
        [InlineData("/home")]
        public async Task AnalyzeAsync_ShouldReturnNoThreat_ForSafeRequest(string path)
        {
            var engine = CreateEngine(SensitivityLevel.Medium);
            var request = CreateRequest(path, null);

            var result = await engine.AnalyzeAsync(request);

            Assert.False(result.IsThreat);
            Assert.Equal("Regex", result.EngineName);
        }

        [Theory]
        [InlineData("/search?query=' OR 1=1 --", "SqlInjection")]
        [InlineData("/comment/<script>alert(1)</script>", "Xss")]
        public async Task AnalyzeAsync_ShouldDetectThreat_ForMaliciousRequest(string path, string expectedThreat)
        {
            var engine = CreateEngine(SensitivityLevel.High);
            var request = CreateRequest(path, null);

            var result = await engine.AnalyzeAsync(request);

            Assert.True(result.IsThreat);
            Assert.Equal(expectedThreat, result.ThreatType.ToString());
            Assert.Equal("Regex", result.EngineName);
        }

        [Fact]
        public async Task AnalyzeAsync_ShouldRespectSensitivityLevel()
        {
            var request = CreateRequest("/etc/../passwd", null);

            var lowOptions = new RegexEngineOptions { Sensitivity = SensitivityLevel.Low };
            var lowEngine = new RegexThreatDetectionEngine(lowOptions, _metrics);
            var lowResult = await lowEngine.AnalyzeAsync(request);
            Assert.False(lowResult.IsThreat); // Low nie powinien wykrywać path traversal

            var highOptions = new RegexEngineOptions { Sensitivity = SensitivityLevel.High };
            var highEngine = new RegexThreatDetectionEngine(highOptions, _metrics);
            var highResult = await highEngine.AnalyzeAsync(request);
            Assert.True(highResult.IsThreat); // High wykrywa path traversal
        }

        [Theory]
        [InlineData("/home")]
        [InlineData("/products?id=12")]
        [InlineData("/search?q=monitor")]
        public async Task AnalyzeAsync_ShouldNotDetectThreat_ForLegitimateTraffic(string path)
        {
            var engine = CreateEngine(SensitivityLevel.High);
            var request = CreateRequest(path, null);

            var result = await engine.AnalyzeAsync(request);

            Assert.False(result.IsThreat);
        }

        [Theory]
        [InlineData("/login?user=admin'--")]
        [InlineData("/search?q=1 OR 1=1")]
        [InlineData("/data?id=1 UNION SELECT password FROM users")]
        public async Task AnalyzeAsync_ShouldDetectSqlInjection(string path)
        {
            var engine = CreateEngine(SensitivityLevel.Medium);
            var request = CreateRequest(path, null);

            var result = await engine.AnalyzeAsync(request);

            Assert.True(result.IsThreat);
            Assert.Equal(ThreatType.SqlInjection, result.ThreatType);
        }

        [Theory]
        [InlineData("<script>alert(1)</script>")]
        [InlineData("<img src=x onerror=alert(1)>")]
        [InlineData("javascript:alert(1)")]
        public async Task AnalyzeAsync_ShouldDetectXss(string payload)
        {
            var engine = CreateEngine(SensitivityLevel.Low);
            var request = CreateRequest("/comment", payload);

            var result = await engine.AnalyzeAsync(request);

            Assert.True(result.IsThreat);
            Assert.Equal(ThreatType.Xss, result.ThreatType);
        }

        [Fact]
        public async Task AnalyzeAsync_PathTraversal_ShouldDependOnSensitivity()
        {
            var request = CreateRequest("/files/../../etc/passwd", null);

            var lowEngine = CreateEngine(SensitivityLevel.Low);
            var lowResult = await lowEngine.AnalyzeAsync(request);
            Assert.False(lowResult.IsThreat);

            var mediumEngine = CreateEngine(SensitivityLevel.Medium);
            var mediumResult = await mediumEngine.AnalyzeAsync(request);
            Assert.True(mediumResult.IsThreat);
        }

        [Theory]
        [InlineData("/ping?host=127.0.0.1; ls")]
        [InlineData("/run?cmd=whoami || id")]
        public async Task AnalyzeAsync_ShouldDetectCommandInjection(string path)
        {
            var engine = CreateEngine(SensitivityLevel.Medium);
            var request = CreateRequest(path, null);

            var result = await engine.AnalyzeAsync(request);

            Assert.True(result.IsThreat);
            Assert.Equal(ThreatType.CommandInjection, result.ThreatType);
        }

        [Fact]
        public async Task AnalyzeAsync_ShouldAlwaysSetExecutionTime()
        {
            var engine = CreateEngine(SensitivityLevel.High);
            var request = CreateRequest("/safe", null);

            var result = await engine.AnalyzeAsync(request);

            Assert.True(result.ExecutionTime.TotalMilliseconds >= 0);
        }


        private RegexThreatDetectionEngine CreateEngine(SensitivityLevel level)
        {
            return new RegexThreatDetectionEngine(
                new RegexEngineOptions { Sensitivity = level },
                new MetricsCollector()
            );
        }

        private HttpRequestData CreateRequest(string path, string? body)
        {
            return new HttpRequestData(
                "GET",
                path,
                new Dictionary<string, string>(),
                body,
                "127.0.0.1"
            );
        }

    }
}
