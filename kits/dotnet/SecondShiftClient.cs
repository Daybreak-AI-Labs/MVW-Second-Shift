using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecondShift;

public enum Risk { Low, Medium, High }
public sealed record AgentBuild(string Version, string ConfigDigest, string Model);
public sealed record RunStart(string Title, string? Summary = null, string? Department = null, AgentBuild? Declared = null);
public sealed record LiveRun(long GoalId, double HeartbeatSeconds);
public sealed record RunResult(string Outcome, decimal CostDollars, long InputTokens,
    long OutputTokens, IReadOnlyList<string> Tools, AgentBuild Declared, string? Summary = null,
    IReadOnlyList<string>? Steps = null, double? DurationSeconds = null, string? IdempotencyKey = null);

public sealed class SecondShiftClient : IDisposable
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RetryBudget = TimeSpan.FromSeconds(140);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly Uri _origin;
    private readonly string _key;

    public SecondShiftClient(string baseUrl, string accessKey)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var url) ||
            (url.Scheme != "https" && !(url.IsLoopback && url.Scheme == "http")) ||
            url.UserInfo.Length != 0 || url.AbsolutePath != "/" ||
            url.Query.Length != 0 || url.Fragment.Length != 0 ||
            string.IsNullOrEmpty(accessKey) || !Regex.IsMatch(accessKey, @"\A[A-Za-z0-9._~+/=\-]+\z"))
            throw new ArgumentException("A Second Shift origin and access key are required.");

        _origin = url;
        _key = accessKey;
        _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
    }

    private async Task<JsonElement> RequestAsync(string path, object? body,
        CancellationToken cancellation, TimeSpan? timeout = null)
    {
        var limit = timeout ?? RetryBudget;
        var clock = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(limit);

        try
        {
            for (var attempt = 0; attempt <= 2; attempt++)
            {
                using var attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                attemptTimeout.CancelAfter(RequestTimeout);
                using var request = new HttpRequestMessage(body is null ? HttpMethod.Get : HttpMethod.Post,
                    new Uri(_origin, "/api/v1/external" + path));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _key);
                if (body is not null)
                    request.Content = JsonContent.Create(body, options: JsonOptions);
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, attemptTimeout.Token);
                if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < 2)
                {
                    var retry = response.Headers.RetryAfter;
                    var delay = retry?.Delta ?? (retry?.Date - DateTimeOffset.UtcNow)
                        ?? TimeSpan.FromMilliseconds(250 << attempt);
                    if (delay >= limit - clock.Elapsed) break;
                    response.Dispose();
                    if (delay > TimeSpan.Zero) await Task.Delay(delay, deadline.Token);
                    continue;
                }
                if (!response.IsSuccessStatusCode) break;
                await using var stream = await response.Content.ReadAsStreamAsync(attemptTimeout.Token);
                using var parsed = await JsonDocument.ParseAsync(stream, cancellationToken: attemptTimeout.Token);
                if (parsed.RootElement.ValueKind == JsonValueKind.Object &&
                    clock.Elapsed < limit && !attemptTimeout.IsCancellationRequested)
                    return parsed.RootElement.Clone();
                break;
            }
        }
        catch (Exception error) when (error is HttpRequestException or IOException or
            JsonException or OperationCanceledException or InvalidOperationException)
        {
            // Transport and parser errors can contain request or response data.
        }
        throw new InvalidOperationException("Second Shift did not return a usable response.");
    }

    private static JsonElement Property(JsonElement reply, string name) =>
        reply.TryGetProperty(name, out var value) ? value : default;

    private static string? Text(JsonElement reply, string name) =>
        Property(reply, name) is { ValueKind: JsonValueKind.String } value ? value.GetString() : null;

    private static long Id(JsonElement reply, string name) =>
        Property(reply, name) is { ValueKind: JsonValueKind.Number } value &&
        value.TryGetInt64(out var id) && id > 0 ? id : 0;

    private static double Number(JsonElement reply, string name) =>
        Property(reply, name) is { ValueKind: JsonValueKind.Number } value &&
        value.TryGetDouble(out var number) && double.IsFinite(number) ? number : 0;

    /// <summary>Returns true only for this proposal. Screen again before each action.</summary>
    public async Task<bool> ScreenAsync(string tool, string detail, Risk risk,
        TimeSpan? approvalWait = null, CancellationToken cancellation = default)
    {
        var wait = approvalWait ?? TimeSpan.FromMinutes(1);
        if (wait < TimeSpan.Zero || wait > TimeSpan.FromMinutes(15) || !Enum.IsDefined(risk)) return false;
        try
        {
            var decision = await RequestAsync("/screen", new { tool, detail, risk = risk.ToString().ToLowerInvariant() },
                cancellation);
            var allowed = Property(decision, "allowed").ValueKind;
            var approval = Property(decision, "requires_approval").ValueKind;
            if (allowed == JsonValueKind.True)
                return approval is JsonValueKind.Undefined or JsonValueKind.False;
            if (allowed != JsonValueKind.False || approval != JsonValueKind.True) return false;
            var id = Id(decision, "approval_id");
            var binding = Text(decision, "approval_binding_sha256");
            if (id == 0 || binding is null || !Regex.IsMatch(binding, @"\A[0-9a-f]{64}\z")) return false;

            var clock = Stopwatch.StartNew();
            while (wait - clock.Elapsed is var remaining && remaining > TimeSpan.Zero)
            {
                var reply = await RequestAsync($"/approvals/{id}?binding_sha256={binding}", null,
                    cancellation, remaining);
                if (Id(reply, "approval_id") != id || Text(reply, "approval_binding_sha256") != binding ||
                    Number(reply, "expires_at") <= DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0)
                    return false;
                var status = Text(reply, "status");
                if (status == "approved") return true;
                if (status != "pending") return false;
                var interval = TimeSpan.FromSeconds(1);
                remaining = wait - clock.Elapsed;
                if (remaining <= interval)
                {
                    if (remaining > TimeSpan.Zero) await Task.Delay(remaining, cancellation);
                    return false;
                }
                await Task.Delay(interval, cancellation);
            }
        }
        catch (Exception error) when (error is InvalidOperationException or OperationCanceledException)
        {
            // The caller may act only on an explicit true.
        }
        return false;
    }

    public async Task<LiveRun> StartRunAsync(RunStart run, CancellationToken cancellation = default)
    {
        var reply = await RequestAsync("/runs/start", run, cancellation);
        var interval = Number(reply, "heartbeat_seconds");
        var id = Receipt(reply);
        if (interval <= 0) throw new InvalidOperationException("Second Shift did not confirm the heartbeat interval.");
        return new LiveRun(id, interval);
    }

    public async Task<bool> HeartbeatAsync(long goalId, CancellationToken cancellation = default)
    {
        if (goalId <= 0) return false;
        try
        {
            var reply = await RequestAsync($"/runs/{goalId}/heartbeat", new { }, cancellation, RequestTimeout);
            return Property(reply, "continue").ValueKind == JsonValueKind.True;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public async Task<long> FinishRunAsync(long goalId, RunResult result, CancellationToken cancellation = default)
    {
        if (goalId <= 0) throw new ArgumentOutOfRangeException(nameof(goalId));
        return Receipt(await RequestAsync($"/runs/{goalId}/finish", ResultBody(result), cancellation), goalId);
    }

    public async Task<long> ReportRunAsync(RunStart run, RunResult result, CancellationToken cancellation = default) =>
        Receipt(await RequestAsync("/runs", ResultBody(result, run), cancellation));

    private static object ResultBody(RunResult result, RunStart? run = null) => new
    {
        Title = run?.Title, Department = run?.Department, Summary = result.Summary ?? run?.Summary,
        result.Outcome, result.CostDollars, result.InputTokens, result.OutputTokens,
        result.Tools, ToolCalls = result.Tools.Count, result.Declared, result.Steps,
        result.DurationSeconds, result.IdempotencyKey,
    };

    private static long Receipt(JsonElement reply, long? expected = null)
    {
        var id = Id(reply, "goal_id");
        if (Property(reply, "ok").ValueKind != JsonValueKind.True || id == 0 ||
            (expected.HasValue && expected.Value != id))
            throw new InvalidOperationException("Second Shift did not confirm the run was recorded.");
        return id;
    }

    public void Dispose() => _http.Dispose();
}
