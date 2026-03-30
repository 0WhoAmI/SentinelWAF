using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Moq;
using SentinelWaf.Application.Interfaces;
using SentinelWaf.Domain.Enums;
using SentinelWaf.Domain.Models;
using SentinelWaf.Middleware.Middleware;

namespace SentinelWaf.UnitTests.Middleware
{
    public class SentinelWafMiddlewareTests
    {
        [Fact]
        public async Task InvokeAsync_WhenAttackDetected_ShouldReturn403Forbidden()
        {
            // ARRANGE
            // Tworzymy fałszywy detektor, który krzyczy: "TO JEST ATAK SQLi!"
            var fakeDetector = new Mock<IAttackDetector>();
            var attackResult = new InspectionResult(true, ThreatLevel.High, AttackType.SqlInjection, DetectionMethod.RegexSimple);

            fakeDetector.Setup(x => x.Analyze(It.IsAny<InspectionRequest>())).Returns(attackResult);

            // To jest funkcja udająca "Kolejny krok" w aplikacji (nasze API)
            RequestDelegate next = (HttpContext hc) => Task.CompletedTask;

            var sut = new SecurityInspectionMiddleware(next);

            // Tworzymy fałszywy kontekst zapytania HTTP
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("api.com");
            httpContext.Request.Path = "/api/zabezpieczony-zasob";
            httpContext.Request.QueryString = new QueryString("?atak=true");
            httpContext.Request.Body = new MemoryStream();
            httpContext.Response.Body = new MemoryStream();

            // ACT
            await sut.InvokeAsync(httpContext, fakeDetector.Object);

            // ASSERT
            httpContext.Response.StatusCode.Should().Be(403);
            httpContext.Response.ContentType.Should().Be("application/json");
        }
    }
}
