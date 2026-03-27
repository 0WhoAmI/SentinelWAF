namespace SentinelWaf.Domain.Models
{
    // Używamy rekordów dla modeli danych, ponieważ są niemutowalne i lekkie
    public record InspectionRequest(
        string IpAddress,
        string Headers,
        string Body,
        string QueryString
    );
}
