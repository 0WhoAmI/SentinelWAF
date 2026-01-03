namespace SentinelWaf.Infrastructure.Options
{
    public enum SensitivityLevel
    {
        Low,
        Medium,
        High
    }

    public sealed class RegexEngineOptions
    {
        public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Medium;
    }
}
