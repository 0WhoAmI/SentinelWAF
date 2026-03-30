using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
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
        public static IServiceCollection AddSentinelWaf(this IServiceCollection services, DetectionMethod selectedMethod)
        {
            // Rejestracja repozytorium metryk
            services.AddSingleton<IMetricsRepository, FileMetricsRepository>();

            // Rejestracja detektora owiniêtego w dekorator mierz¹cy czas
            services.AddSingleton<IAttackDetector>(provider =>
            {
                IAttackDetector innerDetector = selectedMethod switch
                {
                    DetectionMethod.RegexSimple => new RegexSimpleDetector(),
                    DetectionMethod.RegexMedium => new RegexMediumDetector(),
                    DetectionMethod.RegexAdvanced => new RegexAdvancedDetector(),

                    DetectionMethod.MachineLearning => new MlNetDetector(
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Detectors", "ML", "MLModels", "WafModel.zip")),

                    // Domyœlny fallback, gdyby coœ posz³o nie tak
                    _ => new RegexSimpleDetector()
                };

                // Zawsze wpinamy nasz wybrany silnik w Dekorator mierz¹cy czas!
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
