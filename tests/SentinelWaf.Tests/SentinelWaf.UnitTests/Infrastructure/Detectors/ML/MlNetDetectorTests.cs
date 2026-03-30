using FluentAssertions;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
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
            act.Should().Throw<FileNotFoundException>()
               .WithMessage($"*WafModel.zip*"); // Oczekujemy, że w wiadomości o błędzie będzie nazwa pliku
        }

        //// --- TEST INTEGRACYJNY ---
        //// Aby ten test zadziałał, musisz w projekcie testowym też mieć folder MLModels/WafModel.zip 
        //// ustawiony na "Copy if newer"!

        //[Fact(Skip = "To jest test integracyjny, wymaga fizycznego pliku modelu WafModel.zip na dysku.")]
        //public void Analyze_WhenGivenSqlInjection_AndModelIsLoaded_ShouldDetectAttack()
        //{
        //    // 1. ARRANGE
        //    string modelPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WafModel.zip");
        //    var sut = new MlNetDetector(modelPath);

        //    var request = new InspectionRequest(
        //        IpAddress: "127.0.0.1",
        //        Method: "GET",
        //        Path: "/login",
        //        QueryString: "?user=admin' OR 1=1--",
        //        Headers: "",
        //        Body: ""
        //    );

        //    // 2. ACT
        //    var result = sut.Analyze(request);

        //    // 3. ASSERT
        //    result.IsAttack.Should().BeTrue();
        //    result.DetectionMethod.Should().Be(DetectionMethod.MachineLearning);
        //}
    }
}
