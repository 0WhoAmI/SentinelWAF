using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Infrastructure.Detectors.ML
{
    public class MlNetDetector : IAttackDetector
    {
        public InspectionResult Analyze(InspectionRequest request)
        {
            // TODO:
            throw new NotImplementedException();
        }
    }
}
