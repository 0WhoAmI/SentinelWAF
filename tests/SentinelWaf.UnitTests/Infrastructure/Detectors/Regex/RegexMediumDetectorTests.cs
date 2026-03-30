using FluentAssertions;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Detectors.Regex;

namespace SentinelWaf.UnitTests.Infrastructure.Detectors.Regex
{
    public class RegexMediumDetectorTests
    {
        private readonly RegexMediumDetector _sut;

        public RegexMediumDetectorTests()
        {
            _sut = new RegexMediumDetector();
        }

        [Theory]
        [InlineData("UNION ALL SELECT null, version()", AttackType.SqlInjection)]
        [InlineData("</script><script>alert(1)</script>", AttackType.CrossSiteScripting)]
        public void Analyze_WhenGivenMediumLevelAttack_ShouldReturnIsAttackTrue(string payload, AttackType expectedAttackType)
        {
            // ARRANGE
            var request = new InspectionRequest(
                IpAddress: "10.0.0.5",
                Method: "GET",
                Path: "/api/files/download",
                QueryString: $"?file={payload}",
                Headers: "User-Agent: Mozilla/5.0",
                Body: ""
            );

            // ACT
            var result = _sut.Analyze(request);

            // ASSERT
            result.IsAttack.Should().BeTrue();
            result.ThreatLevel.Should().Be(ThreatLevel.Medium);
            result.AttackType.Should().Be(expectedAttackType);
            result.DetectionMethod.Should().Be(DetectionMethod.RegexMedium);
        }

        [Fact]
        public void Analyze_WhenGivenSafePayload_ShouldReturnIsAttackFalse()
        {
            // ARRANGE
            var request = new InspectionRequest(
                IpAddress: "10.0.0.5",
                Method: "GET",
                Path: "/api/files/download",
                QueryString: "",
                Headers: "User-Agent: Mozilla/5.0",
                Body: "I drop my bag"
            );

            // ACT
            var result = _sut.Analyze(request);

            // ASSERT
            result.IsAttack.Should().BeFalse();
            result.ThreatLevel.Should().Be(ThreatLevel.None);
            result.DetectionMethod.Should().Be(DetectionMethod.RegexMedium);
        }
    }
}
