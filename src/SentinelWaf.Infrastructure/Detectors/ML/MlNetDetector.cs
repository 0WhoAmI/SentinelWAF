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

            // Pakujemy nasz tekst w obiekt wejściowy
            WafModelInput input = new WafModelInput { Payload = payloadToAnalyze };

            // PYTAMY SZTUCZNĄ INTELIGENCJĘ O ZDANIE
            WafModelOutput prediction = _predictionEngine.Predict(input);

            // Zamieniamy tekst od ML (np. "SqlInjection") na nasz Enum
            Enum.TryParse<AttackType>(prediction.PredictedCategory, out var predictedAttackType);

            // W Multiclass, najwyższa wartość w tablicy Scores to pewność (Confidence) przewidzianej klasy
            float maxScore = prediction.Scores.Max();

            // Tłumaczymy pewność na ThreatLevel
            ThreatLevel level;
            if (predictedAttackType == AttackType.None)
            {
                level = ThreatLevel.None;
            }
            else
            {
                if (maxScore >= 0.85f) level = ThreatLevel.High;
                else if (maxScore >= 0.60f) level = ThreatLevel.Medium;
                else level = ThreatLevel.Low;
            }

            bool isAttack = level != ThreatLevel.None;

            return new InspectionResult(isAttack, level, predictedAttackType, DetectionMethod.MachineLearning);
        }
    }
}
