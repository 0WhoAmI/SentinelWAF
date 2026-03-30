using FluentAssertions;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Detectors.Regex;

namespace SentinelWaf.UnitTests.Infrastructure.Detectors.Regex
{
    public class RegexSimpleDetectorTests
    {
        // SUT = System Under Test
        private readonly RegexSimpleDetector _sut;

        public RegexSimpleDetectorTests()
        {
            _sut = new RegexSimpleDetector();
        }

        [Theory]
        [InlineData("SELECT * FROM users", AttackType.SqlInjection)]
        [InlineData("<script>alert('xss')</script>", AttackType.CrossSiteScripting)]
        public void Analyze_WhenGivenMaliciousPayload_ShouldReturnIsAttackTrue(string payload, AttackType expectedAttackType)
        {
            // ARRANGE
            var request = new InspectionRequest(
                IpAddress: "192.168.1.100",
                Method: "POST",
                Path: "/api/comments",
                QueryString: "",
                Headers: "Content-Type: application/json",
                Body: payload
            );

            // ACT
            var result = _sut.Analyze(request);

            // ASSERT
            result.IsAttack.Should().BeTrue();
            result.AttackType.Should().Be(expectedAttackType);
        }

        [Fact]
        public void Analyze_WhenGivenSafePayload_ShouldReturnIsAttackFalse()
        {
            // ARRANGE
            var request = new InspectionRequest(
               IpAddress: "192.168.1.100",
               Method: "POST",
               Path: "/api/comments",
               QueryString: "",
               Headers: "Content-Type: application/json",
               Body: "Jan Kowalski"
           );

            // ACT
            var result = _sut.Analyze(request);

            // ASSERT
            result.IsAttack.Should().BeFalse();
            result.AttackType.Should().Be(AttackType.None);
        }
    }
}
