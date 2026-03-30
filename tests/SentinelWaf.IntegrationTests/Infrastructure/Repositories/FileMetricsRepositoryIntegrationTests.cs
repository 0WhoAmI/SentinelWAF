using FluentAssertions;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Metrics;

namespace SentinelWaf.IntegrationTests.Infrastructure.Repositories
{
    public class FileMetricsRepositoryIntegrationTests
    {
        [Fact]
        public async Task SaveAsync_ShouldWriteMetricsToPhysicalCsvFile()
        {
            // ARRANGE
            var sut = new FileMetricsRepository();

            var metrics = new PerformanceMetrics(
                DetectionMethod: DetectionMethod.RegexAdvanced,
                ExecutionTimeMs: 12.5,
                IsAttack: true,
                AttackType: AttackType.SqlInjection,
                Timestamp: DateTime.UtcNow
            );

            string expectedFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "waf_performance_metrics.csv");

            // ACT
            await sut.SaveAsync(metrics);

            // ASSERT
            File.Exists(expectedFilePath).Should().BeTrue("Ponieważ repozytorium powinno stworzyć fizyczny plik CSV na dysku.");

            // Odczytujemy zawartość pliku
            string fileContent = await File.ReadAllTextAsync(expectedFilePath);

            // Sprawdzamy, czy nasze dane faktycznie tam są (szukamy fragmentów tekstu w CSV)
            fileContent.Should().Contain("12.5");
            fileContent.Should().Contain("SqlInjection");
            fileContent.Should().Contain("RegexAdvanced");

            File.Delete(expectedFilePath);
        }
    }
}
