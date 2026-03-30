namespace SentinelWaf.Domain.Models
{
    // Używamy rekordów dla modeli danych, ponieważ są niemutowalne i lekkie
    public record InspectionRequest(
        string IpAddress,
        string Method,
        string Path,
        string QueryString,
        string Headers,
        string Body
    );
}
