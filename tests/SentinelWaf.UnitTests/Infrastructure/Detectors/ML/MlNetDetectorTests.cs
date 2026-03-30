using FluentAssertions;
using SentinelWaf.Infrastructure.Detectors.ML;

namespace SentinelWaf.UnitTests.Infrastructure.Detectors.ML
{
    public class MlNetDetectorTests
    {
        [Fact]
        public void Constructor_WhenModelFileDoesNotExist_ShouldThrowFileNotFoundException()
        {
            // ARRANGE
            string fakePath = "C:/Sciezka/Ktora/Nie/Istnieje/FakeModel.zip";

            // ACT
            // Używamy akcji (Action), żeby złapać wyjątek rzucany przez konstruktor
            Action act = () => new MlNetDetector(fakePath);

            // ASSERT
            // Sprawdzamy, czy aplikacja faktycznie "wybuchła" z właściwym błędem.
            act.Should().Throw<IOException>();
        }
    }
}
