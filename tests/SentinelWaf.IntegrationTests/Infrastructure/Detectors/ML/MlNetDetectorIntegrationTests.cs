using FluentAssertions;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Detectors.ML;

namespace SentinelWaf.IntegrationTests.Infrastructure.Detectors.ML
{
    public class MlNetDetectorIntegrationTests
    {
        [Fact]
        public void Analyze_WhenGivenSqlInjection_AndModelIsLoaded_ShouldDetectAttack()
        {
            // ARRANGE
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

            string relativePath = Path.Combine(
                "..", "..", "..", "..", "..", // Wychodzimy z net8.0 -> Debug -> bin -> IntegrationTests -> tests
                "src",
                "SentinelWaf.Infrastructure",
                "Detectors",
                "ML",
                "MLModels",
                "WafModel.zip"
            );

            string modelPath = Path.GetFullPath(Path.Combine(baseDirectory, relativePath));

            var sut = new MlNetDetector(modelPath);

            var request = new InspectionRequest(
                IpAddress: "203.0.113.50",
                Method: "GET",
                Path: "/api/products",
                QueryString: "?id=1' OR 1=1--",
                Headers: "User-Agent: Mozilla/5.0",
                Body: ""
            );

            // ACT
            var result = sut.Analyze(request);

            // ASSERT
            result.IsAttack.Should().BeTrue();
            result.DetectionMethod.Should().Be(DetectionMethod.MachineLearning);
            result.AttackType.Should().Be(AttackType.SqlInjection);
            result.ThreatLevel.Should().Be(ThreatLevel.High);
        }
    }
}
