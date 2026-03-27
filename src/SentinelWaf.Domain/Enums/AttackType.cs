namespace SentinelWaf.Domain.Enums
{
    public enum AttackType
    {
        None,               // Brak ataku (bezpieczne)
        SqlInjection,       // SQLi
        CrossSiteScripting, // XSS
        PathTraversal,      // LFI/RFI, np. ../../etc/passwd
        CommandInjection,   // Wstrzykiwanie komend basha/cmd
        AnomalyUnknown      // Model ML wie, ¿e coœ jest nie tak, ale nie potrafi sklasyfikowaæ
    }
}
