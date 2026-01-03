using Moq;
using SentinelWaf.Application.Pipelines;
using SentinelWaf.Domain.Abstractions;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Tests.Application
{
    public class DetectionPipelineTests
    {
        [Fact]
        public async Task ExecuteAsync_Should_ReturnResultsFromAllEngines()
        {
            // Arrange
            var request = new HttpRequestData("GET", "/test", new Dictionary<string, string>(), "", "127.0.0.1");

            var engine1 = new Mock<IThreatDetectionEngine>();
            engine1.Setup(e => e.AnalyzeAsync(request, default))
                   .ReturnsAsync(ThreatDetectionResult.NoThreat("Engine1", TimeSpan.Zero));

            var engine2 = new Mock<IThreatDetectionEngine>();
            engine2.Setup(e => e.AnalyzeAsync(request, default))
                   .ReturnsAsync(ThreatDetectionResult.NoThreat("Engine2", TimeSpan.Zero));

            var pipeline = new DetectionPipeline(new[] { engine1.Object, engine2.Object });

            // Act
            var results = await pipeline.ExecuteAsync(request);

            // Assert
            Assert.Equal(2, results.Count);
            Assert.Contains(results, r => r.EngineName == "Engine1");
            Assert.Contains(results, r => r.EngineName == "Engine2");
        }
    }
}
