using Microsoft.AspNetCore.Builder;
using SentinelWaf.Middleware.Middleware;

namespace SentinelWaf.Middleware.Extensions
{
    public static class SentinelWafExtensions
    {
        public static IApplicationBuilder UseSentinelWaf(this IApplicationBuilder app)
        {
            return app.UseMiddleware<SentinelWafMiddleware>();
        }
    }
}
