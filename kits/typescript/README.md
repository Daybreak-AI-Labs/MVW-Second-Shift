# Second Shift client for TypeScript

Use Node.js 22 or later. Run `npm ci && npm test` in this directory to build
and run the mock gateway tests. Import from the built `dist/index.js` or add
`index.ts` to your agent's project. The client has no runtime dependencies.

Enroll the agent on the Second Shift **Outside agents** page, mint its REST
access key, and put the origin and key in your agent's secret-backed
configuration. Use HTTPS in production. This ten-line example assumes
`lookup` and the declared build metadata come from your agent.

```ts
import { SecondShiftClient } from "./dist/index.js";
const client = new SecondShiftClient(process.env.SECOND_SHIFT_URL!, process.env.SECOND_SHIFT_ACCESS_KEY!);
const run = await client.startRun({ title: "Lookup" });
if (!await client.heartbeat(run.goalId)) throw new Error("Stop the run");
const approved = await client.screen("lookup", "Look up the current record", "low");
const allowed = approved && await client.heartbeat(run.goalId);
if (allowed) await lookup();
await client.finishRun(run.goalId, { outcome: allowed ? "success" : "failure",
  cost_dollars: 0, input_tokens: 0, output_tokens: 0, tools: allowed ? ["lookup"] : [],
  declared: { version: "1.2.0", config_digest: "sha256:...", model: "my-model" } });
```

- Screen the exact action each time and act only on `true`. The client polls
  with the binding from the screen response. Approval wait defaults to 60
  seconds. Set the optional fourth argument in milliseconds to shorten it
  or extend it up to 15 minutes.
- Send heartbeats at the returned `heartbeatSeconds` interval, including
  while waiting for a decision or doing a long step. A `false` heartbeat
  means stop and cancel running work where possible. Check again after
  approval and before the action. The client leaves scheduling and
  cancellation of the agent's own work to the caller.
- For a completed run use `reportRun({ title, ...result })`. Put one tool name
  per call in `tools`, including repeats. For a completed-run retry after an
  uncertain response, reuse the same `idempotency_key` and payload. For a
  live run, use the same ID and result when retrying its finish.
- An HTTP attempt times out after 10 seconds. For 429 or a marked capacity refusal, the client
  waits for `Retry-After` before retrying, up to two retries within 140 seconds total.
  A heartbeat has 10 seconds total and approval polls share the approval
  deadline. An indeterminate screen or heartbeat returns `false`.
  Run start, finish and reporting throw a generic error for an unusable
  response. The client never prints the access key or the response body.
