using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SentinelWaf.Application.Interfaces;
using SentinelWaf.Infrastructure.Decorators;
using SentinelWaf.Infrastructure.Detectors.ML;
using SentinelWaf.Infrastructure.Detectors.Regex;
using SentinelWaf.Infrastructure.Metrics;
using SentinelWaf.Middleware.Middleware;

namespace SentinelWaf.Middleware.Extensions
{
    public static class SentinelWafExtensions
    {
        /// <summary>
        /// Dodaje wszystkie serwisy WAF-a do kontenera wstrzykiwania zale¿noœci (DI).
        /// </summary>
        public static IServiceCollection AddSentinelWaf(this IServiceCollection services)
        {
            // Rejestracja repozytorium metryk
            services.AddSingleton<IMetricsRepository, FileMetricsRepository>();

            // Rejestracja detektora owiniêtego w dekorator mierz¹cy czas
            services.AddSingleton<IAttackDetector>(provider =>
            {
                //var mlDetector = new MlNetDetector("C:\\Sciezka\\Do\\Twojego\\model.zip");
                //var metricsRepo = provider.GetRequiredService<IMetricsRepository>();
                //return new PerformanceMeasureDecorator(mlDetector, metricsRepo);

                var innerDetector = new RegexSimpleDetector(); // TODO: W przysz³oœci tu wepne ML
                var metricsRepo = provider.GetRequiredService<IMetricsRepository>();

                return new PerformanceMeasureDecorator(innerDetector, metricsRepo);
            });

            return services;
        }

        /// <summary>
        /// Wpina WAF-a do potoku zapytañ HTTP aplikacji.
        /// </summary>
        public static IApplicationBuilder UseSentinelWaf(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SecurityInspectionMiddleware>();
        }
    }
}
