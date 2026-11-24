using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using SecondShift;

const string key = "test-agent-key";
const string root = "/api/v1/external";
var binding = new string('a', 64);
var parked = Json(new { allowed = false, requires_approval = true, approval_id = 7, approval_binding_sha256 = binding });
var receipt = Json(new { ok = true, goal_id = 42 });
var run = new RunStart("Check item");
var result = new RunResult("success", 0.12m, 100, 25, ["lookup", "lookup"],
    new AgentBuild("1.2", "sha256:abc", "model-a"));
var replies = new ConcurrentQueue<(int Status, string Body, string? RetryAfter)>();
var requests = new ConcurrentQueue<(string Method, string Path, string Bearer, string Body)>();

var builder = WebApplication.CreateBuilder();
builder.Logging.ClearProviders();
builder.WebHost.UseUrls("http://127.0.0.1:0");
await using var server = builder.Build();
server.Run(async context =>
{
    var request = context.Request;
    using var reader = new StreamReader(request.Body);
    requests.Enqueue((request.Method, request.Path + request.QueryString, request.Headers.Authorization.ToString(),
        await reader.ReadToEndAsync()));
    if (!replies.TryDequeue(out var reply))
    {
        context.Response.StatusCode = 500;
        return;
    }
    context.Response.StatusCode = reply.Status;
    context.Response.ContentType = "application/json";
    if (reply.RetryAfter is not null) context.Response.Headers.RetryAfter = reply.RetryAfter;
    if (reply.Status == 302) context.Response.Headers.Location = "/other";
    await context.Response.WriteAsync(reply.Body);
});
await server.StartAsync();
var origin = server.Urls.Single();
using var client = new SecondShiftClient(origin, key);

Reply(200, """{"allowed":true}""");
Reply(200, """{"allowed":false}""");
Check(await Screen(), "explicit allow");
Check(!await Screen(), "explicit deny");
var screen = Take("POST", "/screen");
using (var body = JsonDocument.Parse(screen))
{
    Check(body.RootElement.GetProperty("tool").GetString() == "lookup", "screen tool");
    Check(body.RootElement.GetProperty("detail").GetString() == "Read item", "screen detail");
    Check(body.RootElement.GetProperty("risk").GetString() == "high", "screen risk");
}
Take("POST", "/screen");

Reply(200, parked);
Reply(200, Approval("pending"));
Reply(200, Approval("approved"));
Check(await Screen(), "pending then matching approval");
Take("POST", "/screen");
Take("GET", "/approvals/7?binding_sha256=" + binding);
Take("GET", "/approvals/7?binding_sha256=" + binding);

foreach (var invalid in new[] { Approval("denied"), Approval("approved", expires: 1),
    Approval("approved", hash: new string('b', 64)), Approval("approved", id: 8), Approval("pending") })
{
    Reply(200, parked);
    Reply(200, invalid);
    Check(!await Screen(TimeSpan.FromMilliseconds(200)), "denied, stale, mismatched or pending at deadline");
    Take("POST", "/screen");
    Take("GET", "/approvals/7?binding_sha256=" + binding);
}

foreach (var body in new[] { "<html>", """{"allowed":"true"}""", """{"allowed":false,"requires_approval":true,"approval_id":7}""" })
{
    Reply(200, body);
    Check(!await Screen(), "malformed response or missing binding");
    Take("POST", "/screen");
}
Reply(302, "{}");
Check(!await Screen(), "redirect fails closed");
Take("POST", "/screen");

Reply(429, "{}", "1");
Reply(200, """{"allowed":true}""");
var timer = Stopwatch.StartNew();
Check(await Screen() && timer.ElapsedMilliseconds >= 950, "delay by Retry-After");
Take("POST", "/screen");
Take("POST", "/screen");
for (var i = 0; i < 3; i++) Reply(429, "{}", "0");
Check(!await Screen(), "bounded retries");
for (var i = 0; i < 3; i++) Take("POST", "/screen");
Reply(429, "{}", "300");
Check(!await Screen(), "Retry-After exceeds request budget");
Take("POST", "/screen");

Reply(201, """{"ok":true,"goal_id":42,"heartbeat_seconds":5}""");
Reply(200, """{"continue":true}""");
Reply(200, """{"continue":false}""");
Reply(200, """{"continue":"true"}""");
Reply(200, receipt);
Reply(201, receipt);
Check(await client.StartRunAsync(run) == new LiveRun(42, 5), "start run");
Check(await client.HeartbeatAsync(42), "heartbeat continues");
Check(!await client.HeartbeatAsync(42), "heartbeat stops");
Check(!await client.HeartbeatAsync(42), "heartbeat malformed fails closed");
Check(await client.FinishRunAsync(42, result) == 42, "finish receipt");
Check(await client.ReportRunAsync(run, result) == 42, "report receipt");
Take("POST", "/runs/start");
for (var i = 0; i < 3; i++) Take("POST", "/runs/42/heartbeat");
CheckResult(Take("POST", "/runs/42/finish"), false);
CheckResult(Take("POST", "/runs"), true);

Check(requests.IsEmpty && replies.IsEmpty, "no unexpected requests");
await server.StopAsync();
Check(!await Screen() && !await client.HeartbeatAsync(42), "unreachable service fails closed");
try
{
    await client.StartRunAsync(run);
    throw new Exception("offline run start must fail");
}
catch (InvalidOperationException e)
{
    Check(e.Message == "Second Shift did not return a usable response." && e.InnerException is null,
        "transport errors omit credentials and response content");
}

Console.WriteLine("All mock gateway checks passed.");

static string Json(object value) => JsonSerializer.Serialize(value);
string Approval(string status, long? expires = null, string? hash = null, int id = 7) =>
    Json(new { status, approval_id = id, approval_binding_sha256 = hash ?? binding,
        expires_at = expires ?? DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds() });
void Reply(int status, string body, string? retry = null) => replies.Enqueue((status, body, retry));
Task<bool> Screen(TimeSpan? wait = null) => client.ScreenAsync("lookup", "Read item", Risk.High, wait);

string Take(string method, string path)
{
    Check(requests.TryDequeue(out var request), "expected a gateway request");
    Check(request.Method == method && request.Path == root + path && request.Bearer == "Bearer " + key,
        "method, path and bearer");
    return request.Body;
}

void CheckResult(string text, bool withTitle)
{
    using var doc = JsonDocument.Parse(text);
    var body = doc.RootElement;
    Check(body.TryGetProperty("title", out var title) == withTitle &&
        (!withTitle || title.GetString() == run.Title), "report title");
    Check(body.GetProperty("outcome").GetString() == result.Outcome, "outcome");
    Check(body.GetProperty("cost_dollars").GetDecimal() == result.CostDollars, "cost");
    Check(body.GetProperty("input_tokens").GetInt64() == result.InputTokens &&
        body.GetProperty("output_tokens").GetInt64() == result.OutputTokens, "tokens");
    Check(body.GetProperty("tool_calls").GetInt32() == 2 &&
        body.GetProperty("tools").EnumerateArray().Select(x => x.GetString()).SequenceEqual(result.Tools), "tools");
    var declared = body.GetProperty("declared");
    Check(declared.GetProperty("version").GetString() == result.Declared.Version &&
        declared.GetProperty("config_digest").GetString() == result.Declared.ConfigDigest &&
        declared.GetProperty("model").GetString() == result.Declared.Model, "declared build");
}

static void Check(bool condition, string expectation)
{
    if (!condition) throw new Exception("Failed check: " + expectation);
}
