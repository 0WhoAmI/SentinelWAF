namespace SentinelWaf.UnitTests.Middleware
{
    public class SentinelWafMiddlewareTests
    {
        //[Fact]
        //public async Task InvokeAsync_WhenAttackDetected_ShouldReturn403Forbidden()
        //{
        //    // ARRANGE
        //    // Tworzymy fałszywy detektor, który krzyczy: "TO JEST ATAK SQLi!"
        //    var fakeDetector = new Mock<IAttackDetector>();
        //    var attackResult = new InspectionResult(true, ThreatLevel.High, AttackType.SqlInjection, DetectionMethod.RegexSimple);
        //    fakeDetector.Setup(x => x.Analyze(It.IsAny<InspectionRequest>())).Returns(attackResult);

        //    // To jest funkcja udająca "Kolejny krok" w aplikacji (nasze API)
        //    RequestDelegate next = (HttpContext hc) => Task.CompletedTask;

        //    var sut = new SecurityInspectionMiddleware(next, fakeDetector.Object);

        //    // Tworzymy fałszywy kontekst zapytania HTTP
        //    var httpContext = new DefaultHttpContext();
        //    httpContext.Request.Method = "POST";
        //    httpContext.Request.Scheme = "http";
        //    httpContext.Request.Host = new HostString("api.com");

        //    // ACT
        //    await sut.InvokeAsync(httpContext);

        //    // ASSERT
        //    // Skoro to był atak, Middleware powinien przerwać działanie i ustawić kod 403!
        //    httpContext.Response.StatusCode.Should().Be(403);
        //}
    }
}
