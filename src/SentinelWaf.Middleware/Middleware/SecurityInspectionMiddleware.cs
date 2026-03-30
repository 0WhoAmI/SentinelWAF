using Microsoft.AspNetCore.Http;
using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Models;
using System.Text;
using System.Text.Json;

namespace SentinelWaf.Middleware.Middleware
{
    public class SecurityInspectionMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityInspectionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IAttackDetector detector)
        {
            // 1. POZWÓL NA WIELOKROTNY ODCZYT BODY (Kluczowe dla WAF!)
            context.Request.EnableBuffering();

            // 2. ODCZYT ZAWARTOŒCI ¯¥DANIA
            string bodyContent = string.Empty;
            if (context.Request.Body.CanRead)
            {
                using var reader = new StreamReader(
                    context.Request.Body,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    bufferSize: 1024,
                    leaveOpen: true); // Zostaw strumieñ otwarty dla kontrolerów!

                bodyContent = await reader.ReadToEndAsync();

                // Przewijamy strumieñ z powrotem na pocz¹tek, ¿eby API mog³o go przeczytaæ
                context.Request.Body.Position = 0;
            }

            var requestModel = new InspectionRequest(
                IpAddress: context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Method: context.Request.Method,
                Path: context.Request.Path.ToString(),
                QueryString: context.Request.QueryString.ToString(),
                Headers: context.Request.Headers.ToString(),
                Body: bodyContent
            );

            // 3. WYS£ANIE DO DETEKTORA (Tu dziej¹ siê pomiary i analiza)
            var result = detector.Analyze(requestModel);

            // 4. LOGIKA ODRZUCANIA ZAPYTAÑ
            if (result.IsAttack)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "application/json";

                var responseJson = JsonSerializer.Serialize(new
                {
                    error = "Access Denied. SentinelWAF blocked this request.",
                    attackType = result.AttackType.ToString(),
                    confidence = result.ThreatLevel.ToString()
                });

                await context.Response.WriteAsync(responseJson);

                // Zwracamy z metody bez wywo³ywania _next(context).
                // Zapytanie GINIE tutaj i nigdy nie dociera do API.
                return;
            }

            // 5. PRZEPUSZCZENIE BEZPIECZNEGO ZAPYTANIA DALEJ
            await _next(context);
        }
    }
}
