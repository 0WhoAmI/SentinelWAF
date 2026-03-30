namespace SentinelWaf.Domain.Helpers
{
    public static class OutputHelper
    {
        public static string GetGlobalOutputDirectory()
        {
            // Zaczynamy w miejscu, gdzie fizycznie odpalił się plik .exe (np. bin/Debug/...)
            var directory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);

            // Wspinamy się w górę drzewa folderów, szukając pliku z rozwiązaniem (.sln)
            while (directory != null && !directory.GetFiles("*.sln").Any())
            {
                directory = directory.Parent;
            }

            // Jeśli nie znajdziemy .sln (np. na produkcji), używamy po prostu obecnego folderu
            string solutionRoot = directory?.FullName ?? AppDomain.CurrentDomain.BaseDirectory;

            // Tworzymy ścieżkę do głównego folderu "Outputs"
            string outputDir = Path.Combine(solutionRoot, "Outputs");

            // Jeśli folder nie istnieje, system sam go dla nas stworzy!
            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            return outputDir;
        }
    }
}
