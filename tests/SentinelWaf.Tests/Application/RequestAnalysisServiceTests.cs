using Moq;
using SentinelWaf.Application.Abstractions;
using SentinelWaf.Application.UseCases;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Tests.Application
{
    public class RequestAnalysisServiceTests
    {
        [Fact]
        public async Task AnalyzeAsync_DelegatesToPipeline()
        {
            // Arrange
            var request = new HttpRequestData("GET", "/home", new Dictionary<string, string>(), null, "127.0.0.1");
            var expectedResults = new List<ThreatDetectionResult> { ThreatDetectionResult.NoThreat("TestEngine", System.TimeSpan.Zero) };

            var pipelineMock = new Mock<IDetectionPipeline>();
            pipelineMock.Setup(p => p.ExecuteAsync(request, default))
                        .ReturnsAsync(expectedResults);

            var service = new RequestAnalysisService(pipelineMock.Object);

            // Act
            var results = await service.AnalyzeAsync(request);

            // Assert
            Assert.Equal(expectedResults, results);
        }
    }
}
