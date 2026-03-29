using Microsoft.ML.Data;

namespace SentinelWaf.Infrastructure.Detectors.ML.Models
{
    // TO ZWRACA NAM MODEL PO OCENIE
    public class WafModelOutput
    {
        [ColumnName("PredictedLabel")]
        public string PredictedCategory { get; set; }

        [ColumnName("Score")]
        public float[] Scores { get; set; }
    }
}
