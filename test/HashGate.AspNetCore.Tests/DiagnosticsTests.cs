using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace HashGate.AspNetCore.Tests;

public class DiagnosticsTests
{
    [Fact]
    public async Task AuthenticateAsync_WhenAuthorizationHeaderIsMissing_DoesNotEmitActivity()
    {
        using var listener = new ActivityListener();
        var activities = new List<Activity>();
        var activityLock = new object();

        listener.ShouldListenTo = source => source.Name == HashGateDiagnostics.SourceName;
        listener.Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded;
        listener.ActivityStopped = activity =>
        {
            lock (activityLock)
                activities.Add(activity);
        };

        ActivitySource.AddActivityListener(listener);

        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers.Remove("Authorization");

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);

        Activity[] capturedActivities;

        lock (activityLock)
            capturedActivities = [.. activities];

        Assert.DoesNotContain(capturedActivities, a => a.OperationName == "HashGate.Authenticate");
    }

    [Fact]
    public async Task AuthenticateAsync_WhenAuthorizationSchemeIsNotHmac_DoesNotEmitActivity()
    {
        using var listener = new ActivityListener();
        var activities = new List<Activity>();
        var activityLock = new object();

        listener.ShouldListenTo = source => source.Name == HashGateDiagnostics.SourceName;
        listener.Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded;
        listener.ActivityStopped = activity =>
        {
            lock (activityLock)
                activities.Add(activity);
        };

        ActivitySource.AddActivityListener(listener);

        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers.Authorization = "Bearer token";

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);

        Activity[] capturedActivities;

        lock (activityLock)
            capturedActivities = [.. activities];

        Assert.DoesNotContain(capturedActivities, a => a.OperationName == "HashGate.Authenticate");
    }

    [Fact]
    public async Task AuthenticateAsync_WhenSignatureIsValid_EmitsSuccessActivity()
    {
        var client = $"diagnostics-success-{Guid.NewGuid():N}";
        const string endpoint = "/orders/42";
        using var listener = new ActivityListener();
        var activities = new List<Activity>();
        var activityLock = new object();

        listener.ShouldListenTo = source => source.Name == HashGateDiagnostics.SourceName;
        listener.Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded;
        listener.ActivityStopped = activity =>
        {
            lock (activityLock)
                activities.Add(activity);
        };

        ActivitySource.AddActivityListener(listener);

        var handler = CreateHandler();
        var context = CreateHttpContext(url: endpoint, client: client);
        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);

        Activity[] capturedActivities;
        lock (activityLock)
            capturedActivities = [.. activities];

        var activity = Assert.Single(capturedActivities, a =>
            a.OperationName == "HashGate.Authenticate"
            && Equals(GetTag(a, HashGateDiagnostics.AuthenticationResultTagName), "success")
            && Equals(GetTag(a, HashGateDiagnostics.ClientTagName), client)
        );

        Assert.Equal("success", GetTag(activity, HashGateDiagnostics.AuthenticationResultTagName));
        Assert.Equal(client, GetTag(activity, HashGateDiagnostics.ClientTagName));
        Assert.Equal(endpoint, GetTag(activity, HashGateDiagnostics.EndpointTagName));
        Assert.Equal(CreateScheme().Name, GetTag(activity, HashGateDiagnostics.AuthenticationSchemeTagName));
        Assert.Equal(ActivityStatusCode.Unset, activity.Status);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenSignatureIsInvalid_EmitsFailureActivity()
    {
        var client = $"diagnostics-failure-{Guid.NewGuid():N}";
        using var listener = new ActivityListener();
        var activities = new List<Activity>();
        var activityLock = new object();

        listener.ShouldListenTo = source => source.Name == HashGateDiagnostics.SourceName;
        listener.Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded;
        listener.ActivityStopped = activity =>
        {
            lock (activityLock)
                activities.Add(activity);
        };

        ActivitySource.AddActivityListener(listener);

        var handler = CreateHandler();
        var context = CreateHttpContext(secretKey: "Test-HMAC-Key", providerKey: "Wrong-Key", client: client);

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);

        Activity[] capturedActivities;

        lock (activityLock)
            capturedActivities = [.. activities];

        var activity = Assert.Single(capturedActivities, a =>
            a.OperationName == "HashGate.Authenticate"
            && Equals(GetTag(a, HashGateDiagnostics.ClientTagName), client)
            && Equals(GetTag(a, HashGateDiagnostics.AuthenticationFailureReasonTagName), "invalid_signature")
        );

        Assert.Equal("failure", GetTag(activity, HashGateDiagnostics.AuthenticationResultTagName));
        Assert.Equal("invalid_signature", GetTag(activity, HashGateDiagnostics.AuthenticationFailureReasonTagName));
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
    }

    [Fact]
    public async Task AuthenticateAsync_RecordsAuthMetrics()
    {
        var client = $"diagnostics-metrics-{Guid.NewGuid():N}";
        const string endpoint = "/metrics/usage";
        var measurements = new List<(string Instrument, long Value, Dictionary<string, object?> Tags)>();
        var measurementLock = new object();

        using var listener = new MeterListener();

        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == HashGateDiagnostics.MeterName
                && instrument.Name is HashGateDiagnostics.AuthenticationRequestsName or HashGateDiagnostics.AuthenticationFailuresName)
                meterListener.EnableMeasurementEvents(instrument);
        };

        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            lock (measurementLock)
                measurements.Add((instrument.Name, measurement, ToDictionary(tags)));
        });

        listener.Start();

        var handler = CreateHandler();
        var context = CreateHttpContext(url: endpoint, secretKey: "Test-HMAC-Key", providerKey: "Wrong-Key", client: client);

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();
        listener.RecordObservableInstruments();

        (string Instrument, long Value, Dictionary<string, object?> Tags)[] capturedMeasurements;

        lock (measurementLock)
            capturedMeasurements = [.. measurements];

        Assert.False(result.Succeeded);

        Assert.Contains(capturedMeasurements, m =>
            m.Instrument == HashGateDiagnostics.AuthenticationRequestsName
            && m.Value == 1
            && Equals(m.Tags[HashGateDiagnostics.AuthenticationResultTagName], "failure")
            && Equals(m.Tags[HashGateDiagnostics.ClientTagName], client)
            && Equals(m.Tags[HashGateDiagnostics.EndpointTagName], endpoint)
            && Equals(m.Tags[HashGateDiagnostics.AuthenticationFailureReasonTagName], "invalid_signature")
        );

        Assert.Contains(capturedMeasurements, m =>
            m.Instrument == HashGateDiagnostics.AuthenticationFailuresName
            && m.Value == 1
            && Equals(m.Tags[HashGateDiagnostics.ClientTagName], client)
            && Equals(m.Tags[HashGateDiagnostics.EndpointTagName], endpoint)
            && Equals(m.Tags[HashGateDiagnostics.AuthenticationFailureReasonTagName], "invalid_signature")
        );
    }

    private static HmacAuthenticationHandler CreateHandler()
    {
        var options = new HmacAuthenticationSchemeOptions();
        var optionsMonitor = new TestOptionsMonitor(options);

        return new HmacAuthenticationHandler(optionsMonitor, new NullLoggerFactory(), UrlEncoder.Default);
    }

    private static AuthenticationScheme CreateScheme()
    {
        return new AuthenticationScheme(
            name: HmacAuthenticationShared.DefaultSchemeName,
            displayName: "HMAC Scheme",
            handlerType: typeof(HmacAuthenticationHandler));
    }

    private static DefaultHttpContext CreateHttpContext(
        string method = "GET",
        string url = "/",
        string? content = null,
        string secretKey = "Test-HMAC-Key",
        string? providerKey = null,
        string client = "client1")
    {
        var context = new DefaultHttpContext();

        var services = new ServiceCollection();
        services.AddSingleton<IHmacKeyProvider>(new DiagnosticsTestHmacKeyProvider(providerKey ?? secretKey));

        context.RequestServices = services.BuildServiceProvider();
        context.Request.Method = method;

        var uri = new Uri("http://localhost" + url, UriKind.Absolute);
        context.Request.Scheme = uri.Scheme;
        context.Request.Host = new HostString(uri.Host, uri.Port);
        context.Request.Path = uri.AbsolutePath;
        context.Request.QueryString = new QueryString(uri.Query);

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        context.Request.Headers.Append(HmacAuthenticationShared.TimeStampHeaderName, timestamp);

        var contentBytes = Encoding.UTF8.GetBytes(content ?? string.Empty);
        var contentHash = SHA256.HashData(contentBytes);
        var contentHashEncoded = Convert.ToBase64String(contentHash);

        context.Request.Body = new MemoryStream(contentBytes);
        context.Request.ContentLength = contentBytes.Length;
        context.Request.Headers.Append(HmacAuthenticationShared.ContentHashHeaderName, contentHashEncoded);

        var nonce = Guid.NewGuid().ToString("N");
        context.Request.Headers.Append(HmacAuthenticationShared.NonceHeaderName, nonce);

        var stringToSign = HmacAuthenticationShared.CreateStringToSign(
            method: context.Request.Method,
            pathAndQuery: context.Request.Path + context.Request.QueryString,
            headerValues: [context.Request.Host.ToString(), timestamp, contentHashEncoded, nonce]
        );

        var signature = HmacAuthenticationShared.GenerateSignature(stringToSign, secretKey);

        context.Request.Headers.Authorization = HmacAuthenticationShared.GenerateAuthorizationHeader(
            client: client,
            signedHeaders: HmacAuthenticationShared.DefaultSignedHeaders,
            signature: signature
        );

        return context;
    }

    private static object? GetTag(Activity activity, string key)
    {
        return activity.TagObjects.SingleOrDefault(tag => tag.Key == key).Value;
    }

    private static Dictionary<string, object?> ToDictionary(ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var dictionary = new Dictionary<string, object?>();
        foreach (var tag in tags)
            dictionary[tag.Key] = tag.Value;

        return dictionary;
    }

    private sealed class DiagnosticsTestHmacKeyProvider(string key = "Test-HMAC-Key") : IHmacKeyProvider
    {
        public ValueTask<ClaimsIdentity> GenerateClaimsAsync(string client, string? scheme = null, CancellationToken cancellationToken = default)
        {
            Claim[] claims = [new Claim(ClaimTypes.Name, client)];
            var identity = new ClaimsIdentity(claims, scheme);

            return ValueTask.FromResult(identity);
        }

        public ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default) => new(key);
    }
}
