namespace SentinelWaf.Domain.Models
{
    public sealed record HttpRequestData(
        string Method,
        string Path,
        IReadOnlyDictionary<string, string> Headers,
        string? Body,
        string ClientIp
    );
}
