using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.ML;
using SentinelWaf.Infrastructure.Detectors.ML.Models;
using System.Globalization;

namespace SentinelWaf.MlTrainer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== ROZPOCZYNAM PROCES TRENOWANIA WAF AI ===");


            // PRZYGOTOWANIE ŚCIEŻEK
            var (tsvPath, zipPath) = SetupDirectories();

            // OBRÓBKA DANYCH
            PrepareDataFromKaggle("Datasets\\Modified_SQL_Dataset.csv", "Datasets\\XSS_dataset.csv", tsvPath);

            // TRENOWANIE MODELU
            TrainModel(tsvPath, zipPath);

            Console.WriteLine("\nNaciśnij dowolny klawisz, aby zakończyć...");
            Console.ReadKey();
        }

        static (string tsvPath, string zipPath) SetupDirectories()
        {
            Console.WriteLine("[1/5] Konfiguracja środowiska pracy...");

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string trainerProjectDir = Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\"));
            string infrastructureDir = Path.GetFullPath(Path.Combine(trainerProjectDir, @"..\..\src\SentinelWaf.Infrastructure"));

            // 1. Zapis datasetu 
            string localOutputDir = Path.Combine(trainerProjectDir, "ModelOutput");
            Directory.CreateDirectory(localOutputDir);
            string tsvPath = Path.Combine(localOutputDir, "dataset.tsv");

            // 2. Publikacja pliku .zip do WAF-a 
            string mlModelsFolder = Path.Combine(infrastructureDir, "Detectors", "ML", "MLModels");
            Directory.CreateDirectory(mlModelsFolder);
            string zipPath = Path.Combine(mlModelsFolder, "WafModel.zip");

            Console.WriteLine($" -> Zbiór danych (TSV) zostanie zapisany w: {tsvPath}");
            Console.WriteLine($" -> Wyuczony model (ZIP) zostanie wgrany do: {zipPath}\n");

            return (tsvPath, zipPath);
        }

        static void PrepareDataFromKaggle(string sqlCsvPath, string xssCsvPath, string outputTsvPath)
        {
            Console.WriteLine("\n[2/5] Wczytywanie i czyszczenie danych...");
            var dataset = new List<string>();
            var csvConfig = new CsvConfiguration(CultureInfo.InvariantCulture)
            {
                HasHeaderRecord = true,
                BadDataFound = null // Ignoruj pojedyncze zepsute wiersze
            };

            // ---- PRZETWARZANIE SQLi ----
            if (File.Exists(sqlCsvPath))
            {
                using var reader = new StreamReader(sqlCsvPath);
                using var csv = new CsvReader(reader, csvConfig);
                csv.Read();
                csv.ReadHeader();
                while (csv.Read())
                {
                    string payload = csv.GetField(0); // Kolumna: Query
                    int label = csv.GetField<int>(1); // Kolumna: Label (0 lub 1)

                    string category = label == 1 ? "SqlInjection" : "None";
                    AddCleanRecord(dataset, payload, category);
                }
                Console.WriteLine("-> Wczytano plik SQLi");
            }

            // ---- PRZETWARZANIE XSS ----
            if (File.Exists(xssCsvPath))
            {
                using var reader = new StreamReader(xssCsvPath);
                using var csv = new CsvReader(reader, csvConfig);
                csv.Read();
                csv.ReadHeader();
                while (csv.Read())
                {
                    string payload = csv.GetField(1); // Kolumna: Sentence (indeks 1, bo kolumna 0 to ID)
                    int label = csv.GetField<int>(2); // Kolumna: Label (0 lub 1)

                    string category = label == 1 ? "CrossSiteScripting" : "None";
                    AddCleanRecord(dataset, payload, category);
                }
                Console.WriteLine("-> Wczytano plik XSS");
            }

            // ---- MIESZANIE (SHUFFLE) ----
            Console.WriteLine("[3/5] Mieszanie 44,000 rekordów (żeby AI uczyło się równomiernie)...");
            var random = new Random(42);
            dataset = dataset.OrderBy(x => random.Next()).ToList();

            // ---- ZAPIS DO TSV ----
            using (var writer = new StreamWriter(outputTsvPath))
            {
                writer.WriteLine("Payload\tLabel"); // Nagłówek dla ML.NET (Label to nazwa kolumny, Payload to tekst)
                foreach (var line in dataset)
                {
                    writer.WriteLine(line);
                }
            }
            Console.WriteLine($"-> Zapisano czysty zbiór {dataset.Count} próbek do {outputTsvPath}");
        }

        static void AddCleanRecord(List<string> dataset, string payload, string category)
        {
            if (string.IsNullOrWhiteSpace(payload))
                return;

            // Usuwamy białe znaki nowej linii i tabulacji, żeby nie zepsuć formatu TSV
            string cleanPayload = payload
                .Replace("\t", " ")
                .Replace("\n", " ")
                .Replace("\r", " ");
            dataset.Add($"{cleanPayload}\t{category}");
        }

        static void TrainModel(string inputTsvPath, string outputZipPath)
        {
            Console.WriteLine("\n[4/5] Budowanie potoku uczenia maszynowego (Multiclass)...");
            var mlContext = new MLContext(seed: 0);

            // Ładowanie naszego pliku TSV
            var dataView = mlContext.Data.LoadFromTextFile<WafModelInput>(
                path: inputTsvPath,
                hasHeader: true,
                separatorChar: '\t'); // Używamy tabulacji

            var pipeline =
                // a) MapValueToKey: Algorytm AI nie rozumie tekstu (np. słowa "SqlInjection").
                // Zamieniamy więc etykiety tekstowe na liczbowe ID (np. "SqlInjection" -> 1, "None" -> 2).
                mlContext.Transforms.Conversion.MapValueToKey("LabelKey", nameof(WafModelInput.Category)) // Mapujemy String -> Id AI

                // b) FeaturizeText: Algorytm nie rozumie wektorów ataku.
                // Ta metoda tnie złośliwy kod na małe kawałki (np. n-gramy), liczy je i zamienia na wektor liczb matematycznych.
                .Append(mlContext.Transforms.Text.FeaturizeText("Features", nameof(WafModelInput.Payload))) // Zamiana tekstu na wektory liczbowe

                // UŻYWAMY ALGORYTMU WIELOKLASOWEGO

                // c) SdcaMaximumEntropy: To jest WŁAŚCIWY ALGORYTM. Tutaj wybieramy nauczyciela.
                // Dostaje on kolumnę z ID ataku ("LabelKey") i wektor liczb zapytania ("Features") i szuka między nimi powiązań.
                .Append(mlContext.MulticlassClassification.Trainers.SdcaMaximumEntropy(
                    labelColumnName: "LabelKey",
                    featureColumnName: "Features"))

                // d) MapKeyToValue: Kiedy model już zgadnie odpowiedź w postaci liczby (np. 1), 
                // zamieniamy ją z powrotem na czytelny tekst (np. "SqlInjection"), żeby WAF to zrozumiał.
                .Append(mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel", "PredictedLabel")); // Mapujemy Id AI -> String

            Console.WriteLine("[5/5] Trenowanie... (Dla 44 tysięcy rekordów to może zająć od kilku do kilkunastu sekund)");
            var model = pipeline.Fit(dataView);

            mlContext.Model.Save(model, dataView.Schema, outputZipPath);
            Console.WriteLine($"\n=== SUKCES! Model sztucznej inteligencji został zapisany do: {outputZipPath} ===");
        }
    }
}
