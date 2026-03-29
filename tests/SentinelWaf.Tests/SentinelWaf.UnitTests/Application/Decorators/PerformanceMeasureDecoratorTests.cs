using FluentAssertions;
using Moq;
using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Decorators;

namespace SentinelWaf.UnitTests.Application.Decorators
{
    public class PerformanceMeasureDecoratorTests
    {
        [Fact]
        public void Analyze_ShouldMeasureTime_AndCallSaveAsyncOnRepository()
        {
            // ARRANGE
            // Tworzymy fałszywy detektor (Kaskadera), który zawsze mówi, że jest bezpiecznie
            var fakeDetector = new Mock<IAttackDetector>();
            var fakeResult = new InspectionResult(false, ThreatLevel.None, AttackType.None, DetectionMethod.RegexSimple);

            // Uczymy kaskadera: "Kiedy ktoś wywoła Analyze, zwróć fakeResult"
            fakeDetector.Setup(x => x.Analyze(It.IsAny<InspectionRequest>())).Returns(fakeResult);

            // Tworzymy fałszywe Repozytorium (żeby nie pisać na dysk)
            var fakeRepository = new Mock<IMetricsRepository>();

            // Tworzymy nasz prawdziwy dekorator, ale wstrzykujemy mu Kaskaderów!
            var sut = new PerformanceMeasureDecorator(fakeDetector.Object, fakeRepository.Object);
            var request = new InspectionRequest("http://api.com", "test", "", "GET");

            // ACT
            var result = sut.Analyze(request);

            // ASSERT
            result.Should().BeEquivalentTo(fakeResult); // Dekorator nie może zmieniać samego wyniku!

            // Najważniejsze: Sprawdzamy, czy Dekorator wywołał metodę SaveAsync() na repozytorium dokładnie 1 raz!
            fakeRepository.Verify(x => x.SaveAsync(
                It.Is<PerformanceMetrics>(m => m.ExecutionTimeMs >= 0 && m.DetectionMethod == DetectionMethod.RegexSimple)
            ), Times.Once);
        }
    }
}
