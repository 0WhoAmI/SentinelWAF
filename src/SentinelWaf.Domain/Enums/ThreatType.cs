namespace SentinelWaf.Domain.Enums
{
    public enum ThreatType
    {
        None,
        SqlInjection,
        Xss,
        CommandInjection,
        PathTraversal,
        Unknown
    }
}
