# Second Shift client for .NET

Use the .NET 8 SDK. Add a project reference to `SecondShift.Client.csproj`.
Run `dotnet run --project tests` here to verify the client against a local
mock gateway. The library uses the .NET runtime libraries.

Enroll the agent on the Second Shift **Outside agents** page, mint its REST
access key, and put the origin and key in your agent's secret-backed
configuration. Use HTTPS in production. This ten-line example assumes
`LookupAsync` and the declared build metadata come from your agent.

```csharp
using SecondShift;
using var client = new SecondShiftClient(Environment.GetEnvironmentVariable("SECOND_SHIFT_URL")!,
    Environment.GetEnvironmentVariable("SECOND_SHIFT_ACCESS_KEY")!);
var run = await client.StartRunAsync(new RunStart("Lookup"));
if (!await client.HeartbeatAsync(run.GoalId)) throw new InvalidOperationException("Stop the run");
var approved = await client.ScreenAsync("lookup", "Look up the current record", Risk.Low);
var allowed = approved && await client.HeartbeatAsync(run.GoalId);
if (allowed) await LookupAsync();
await client.FinishRunAsync(run.GoalId, new RunResult(allowed ? "success" : "failure", 0, 0, 0,
    allowed ? ["lookup"] : [], new AgentBuild("1.2.0", "sha256:...", "my-model")));
```

- Screen the exact action each time and act only on `true`. The client polls
  with the binding from the screen response. Approval wait defaults to 60
  seconds. Pass `approvalWait` to shorten it or extend it up to 15 minutes.
- Send heartbeats at the returned `HeartbeatSeconds` interval, including
  while waiting for a decision or doing a long step. A `false` heartbeat
  means stop and cancel running work where possible. Check again after
  approval and before the action. The client leaves scheduling and
  cancellation of the agent's own work to the caller.
- For a completed run use `ReportRunAsync(new RunStart(title), result)`.
  Put one tool name per call in `Tools`, including repeats. For a completed-run
  retry after an uncertain response, reuse the same `IdempotencyKey` and
  payload. For a live run, use the same ID and result when retrying its finish.
- An HTTP attempt times out after 10 seconds. For 429 or a marked capacity refusal, the client
  waits for `Retry-After` before retrying, up to two retries within 140 seconds total.
  A heartbeat has 10 seconds total and approval polls share the approval
  deadline. An indeterminate screen or heartbeat returns `false`.
  Run start, finish and reporting throw a generic error for an unusable
  response. The client never prints the access key or the response body.
