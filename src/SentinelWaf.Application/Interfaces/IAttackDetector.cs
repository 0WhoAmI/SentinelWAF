using SentinelWaf.Domain.Models;

namespace SentinelWaf.Application.Interfaces
{
    // WZORZEC STRATEGIA: Wspólny interfejs dla każdego algorytmu
    public interface IAttackDetector
    {
        InspectionResult Analyze(InspectionRequest request);
    }
}
