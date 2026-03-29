using Microsoft.ML.Data;

namespace SentinelWaf.Infrastructure.Detectors.ML.Models
{
    // TO DAJEMY MODELOWI DO OCENY
    public class WafModelInput
    {
        // Atrybut mówi, że w naszych danych treningowych to była pierwsza kolumna tekstu
        [LoadColumn(0)]
        public string Payload { get; set; }

        [LoadColumn(1)]
        public string Category { get; set; }
    }
}
