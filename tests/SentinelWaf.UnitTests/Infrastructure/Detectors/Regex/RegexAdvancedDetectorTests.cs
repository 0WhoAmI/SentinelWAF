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
        // ZAAWANSOWANY XSS (Zaciemniony, bez spacji, dziwne tagi)
        [InlineData("<svg/onload=alert(1)>", AttackType.CrossSiteScripting)]
        [InlineData("<img src=x onerror=prompt(document.cookie);>", AttackType.CrossSiteScripting)]
        [InlineData("javascript://%250Aalert(1)", AttackType.CrossSiteScripting)]

        // ZAAWANSOWANE SQLi (Time-based, stacked queries, procedury)
        [InlineData("1' AND SLEEP(10)--", AttackType.SqlInjection)]
        [InlineData("'; EXEC xp_cmdshell('dir')--", AttackType.SqlInjection)]
        [InlineData("1' AND WAITFOR DELAY '0:0:5'--", AttackType.SqlInjection)]
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
