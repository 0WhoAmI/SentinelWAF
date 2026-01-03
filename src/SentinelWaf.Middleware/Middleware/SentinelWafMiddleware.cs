using Microsoft.AspNetCore.Http;
using SentinelWaf.Application.Abstractions;
using SentinelWaf.Domain.Models;

namespace SentinelWaf.Middleware.Middleware
{
    public sealed class SentinelWafMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IRequestAnalysisService _analysisService;

        public SentinelWafMiddleware(RequestDelegate next, IRequestAnalysisService analysisService)
        {
            _next = next;
            _analysisService = analysisService;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var request = new HttpRequestData(
                context.Request.Method,
                context.Request.Path,
                context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                null,
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown"
            );

            var results = await _analysisService.AnalyzeAsync(request, context.RequestAborted);

            // TODO: Faza 3 – decyzja BLOCK / ALLOW

            await _next(context);
        }
    }
}
