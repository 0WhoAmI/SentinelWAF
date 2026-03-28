using Microsoft.ML;
using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Infrastructure.Detectors.ML.Models;

namespace SentinelWaf.Infrastructure.Detectors.ML
{
    public class MlNetDetector : IAttackDetector
    {
        // "Silnik predykcji" - to on wykonuje właściwą pracę
        private readonly PredictionEngine<WafModelInput, WafModelOutput> _predictionEngine;

        // W konstruktorze podajemy ścieżkę do pliku z wyuczonym modelem (np. "model.zip")
        public MlNetDetector(string modelPath)
        {
            // 1. Inicjalizujemy środowisko ML.NET
            var mlContext = new MLContext();

            // 2. Ładujemy zapisaną "wiedzę" z pliku .zip do pamięci
            ITransformer mlModel = mlContext.Model.Load(modelPath, out var modelInputSchema);

            // 3. Tworzymy silnik predykcji, mówiąc mu jakich klas wejścia/wyjścia używamy
            _predictionEngine = mlContext.Model.CreatePredictionEngine<WafModelInput, WafModelOutput>(mlModel);
        }
        public InspectionResult Analyze(InspectionRequest request)
        {
            // Łączymy to, co chcemy sprawdzić (Body + QueryString)
            string payloadToAnalyze = $"{request.QueryString} {request.Body}";

            if (string.IsNullOrWhiteSpace(payloadToAnalyze))
                return new InspectionResult(false, ThreatLevel.None, AttackType.None, DetectionMethod.MachineLearning);

            // 1. Pakujemy nasz tekst w obiekt wejściowy
            var input = new WafModelInput { Payload = payloadToAnalyze };

            // 2. PYTAMY SZTUCZNĄ INTELIGENCJĘ O ZDANIE! (magia dzieje się tutaj)
            var prediction = _predictionEngine.Predict(input);

            // 3. Tłumaczymy to, co wypluł model na nasz WAF-owy ThreatLevel
            ThreatLevel level;
            if (prediction.Probability >= 0.90f)
                level = ThreatLevel.High;    // AI jest na >90% pewne, że to atak
            else if (prediction.Probability >= 0.70f)
                level = ThreatLevel.Medium;  // AI uważa to za wysoce podejrzane
            else if (prediction.Probability >= 0.50f)
                level = ThreatLevel.Low;     // Pół na pół
            else
                level = ThreatLevel.None;    // AI uważa, że to bezpieczny ruch

            bool isAttack = level != ThreatLevel.None;

            // Zwracamy piękny obiekt, z którym nasz Middleware będzie umiał pracować!
            // Uwaga: Ponieważ klasyfikator jest binarny (zły/dobry), typ ataku to AnomalyUnknown
            return new InspectionResult(isAttack, level, AttackType.AnomalyUnknown, DetectionMethod.MachineLearning);
        }
    }
}
