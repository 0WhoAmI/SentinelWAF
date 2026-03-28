using Microsoft.ML;
using SentinelWaf.Infrastructure.Detectors.ML.Models;

namespace SentinelWaf.MlTrainer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Rozpoczynam trening modelu sztucznej inteligencji...");

            // Środowisko ML.NET (ustawiamy seed, żeby za każdym razem wyniki były powtarzalne)
            var mlContext = new MLContext(seed: 0);

            // KROK 1: WCZYTANIE DANYCH Z PLIKU
            Console.WriteLine("1. Wczytywanie danych z dataset.csv...");
            var dataView = mlContext.Data.LoadFromTextFile<WafModelInput>(
                path: "dataset.csv",
                hasHeader: true,
                separatorChar: ',');

            // KROK 2: BUDOWANIE POTOKU (PIPELINE)
            // Sztuczna inteligencja nie rozumie tekstu (liter). Rozumie tylko liczby.
            // FeaturizeText zamienia nasze wyrażenia SQLi i XSS na wektory liczbowe.
            var pipeline = mlContext.Transforms.Text.FeaturizeText("Features", nameof(WafModelInput.Payload))
                // Następnie doklejamy algorytm klasyfikacji binarnej (SdcaLogisticRegression to klasyk dla tekstu)
                .Append(mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(
                    labelColumnName: nameof(WafModelInput.IsMalicious),
                    featureColumnName: "Features"));

            // KROK 3: TRENOWANIE (Nauka)
            Console.WriteLine("2. Trenowanie algorytmu (to może chwilę potrwać)...");
            var model = pipeline.Fit(dataView);

            // KROK 4: ZAPIS DO PLIKU .ZIP
            var modelPath = "WafModel.zip";
            Console.WriteLine($"3. Zapisywanie modelu do pliku: {modelPath}...");
            mlContext.Model.Save(model, dataView.Schema, modelPath);

            Console.WriteLine("Gotowe! Skopiuj plik WafModel.zip do swojego WAF-a.");
        }
    }
}
