using Microsoft.ML.Data;

namespace SentinelWaf.Infrastructure.Detectors.ML.Models
{
    // TO ZWRACA NAM MODEL PO OCENIE
    public class WafModelOutput
    {
        // Prawdopodobieństwo (od 0.0 do 1.0)
        [ColumnName("Probability")]
        public float Probability { get; set; }

        // Wynik zero-jedynkowy (true = atak, false = bezpieczne)
        [ColumnName("PredictedLabel")]
        public bool IsMalicious { get; set; }

        [ColumnName("Score")]
        public float Score { get; set; }
    }
}
