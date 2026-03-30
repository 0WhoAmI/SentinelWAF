using FluentAssertions;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Detectors.Regex;

namespace SentinelWaf.UnitTests.Infrastructure.Detectors.Regex
{
    public class RegexAdvancedDetectorTests
    {
        private readonly RegexAdvancedDetector _sut;

        public RegexAdvancedDetectorTests()
        {
            _sut = new RegexAdvancedDetector();
        }

        [Theory]
        [InlineData("<img src=x onerror=prompt(document.cookie);>", AttackType.CrossSiteScripting)]
        [InlineData("; rm -rf /", AttackType.CommandInjection)] // Próba usunięcia serwera (Linux)
        [InlineData("127.0.0.1 | dir", AttackType.CommandInjection)] // Próba ataku na Windows
        public void Analyze_WhenGivenAdvancedAttack_ShouldDetectHighThreat(string payload, AttackType expectedAttackType)
        {
            // ARRANGE
            var request = new InspectionRequest(
                IpAddress: "192.168.1.200",
                Method: "POST",
                Path: "/api/system/ping",
                QueryString: "",
                Headers: "Content-Type: application/json",
                Body: $"{{\"target\": \"{payload}\"}}"
            );

            // ACT
            var result = _sut.Analyze(request);

            // ASSERT
            result.IsAttack.Should().BeTrue();
            result.ThreatLevel.Should().Be(ThreatLevel.High);
            result.AttackType.Should().Be(expectedAttackType);
            result.DetectionMethod.Should().Be(DetectionMethod.RegexAdvanced);
        }
    }
}
