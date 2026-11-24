import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { SecondShiftClient } from "../dist/index.js";

const key = "test-agent-key";
const root = "/api/v1/external";
const binding = "a".repeat(64);
const parked = {
  allowed: false, requires_approval: true, approval_id: 7, approval_binding_sha256: binding,
};
const approval = status => ({
  approval_id: 7, approval_binding_sha256: binding, status, expires_at: Date.now() / 1000 + 60,
});
const result = {
  outcome: "success", cost_dollars: 0.12, input_tokens: 100, output_tokens: 25,
  tools: ["lookup", "lookup"], declared: { version: "1.2", config_digest: "sha256:abc", model: "model-a" },
};

async function mock(t, ...replies) {
  const requests = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    requests.push([request.method, request.url, request.headers.authorization, body && JSON.parse(body)]);
    const [status, payload, headers] = replies.shift() ?? [500, {}];
    response.writeHead(status, { "Content-Type": "application/json", ...headers });
    response.end(typeof payload === "string" ? payload : JSON.stringify(payload));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return [new SecondShiftClient(`http://127.0.0.1:${server.address().port}`, key), requests, server];
}

test("screens exact proposals with a bearer, and denies explicit refusal", async t => {
  const [client, requests] = await mock(t, [200, { allowed: true }], [200, { allowed: false }]);
  assert.equal(await client.screen("lookup", "Read item", "low"), true);
  assert.equal(await client.screen("delete", "Delete item", "high"), false);
  assert.deepEqual(requests[0], [
    "POST", root + "/screen", "Bearer " + key, { tool: "lookup", detail: "Read item", risk: "low" },
  ]);
});

test("waits for the matching approval after a pending response", async t => {
  const [client, requests] = await mock(t, [200, parked], [200, approval("pending")], [200, approval("approved")]);
  assert.equal(await client.screen("lookup", "Read item", "high"), true);
  assert.deepEqual(requests.slice(1), Array(2).fill([
    "GET", root + "/approvals/7?binding_sha256=" + binding, "Bearer " + key, "",
  ]));
});

test("denied, expired, wrong and missing bindings, and a bounded pending wait fail closed", async t => {
  for (const reply of [
    approval("denied"), { ...approval("approved"), expires_at: 1 },
    { ...approval("approved"), approval_binding_sha256: "b".repeat(64) },
    { ...approval("approved"), approval_id: 8 },
    approval("pending"),
  ]) {
    const [client] = await mock(t, [200, parked], [200, reply]);
    assert.equal(await client.screen("lookup", "", "high", 200), false);
  }
  const [client, requests] = await mock(t, [200, { ...parked, approval_binding_sha256: undefined }]);
  assert.equal(await client.screen("lookup", "", "high"), false);
  assert.equal(requests.length, 1);
});

test("malformed, unreachable and redirected responses fail closed", async t => {
  const [client, requests, server] = await mock(t, [200, "<html>"], [200, { allowed: "true" }],
    [302, {}, { Location: "/other" }], [200, { continue: "true" }]);
  for (let i = 0; i < 3; i++) assert.equal(await client.screen("lookup", "", "low"), false);
  assert.equal(requests.length, 3);
  assert.equal(await client.heartbeat(42), false);
  const origin = `http://127.0.0.1:${server.address().port}`;
  await new Promise(resolve => server.close(resolve));
  const offline = new SecondShiftClient(origin, key);
  assert.equal(await offline.screen("lookup", "", "low"), false);
  await assert.rejects(offline.startRun({ title: "Offline" }), { message: "Second Shift did not return a usable response." });
});

test("respects Retry-After, caps retries, and stops when Retry-After exceeds the budget", async t => {
  const [client, requests] = await mock(t, [429, {}, { "Retry-After": "1" }], [200, { allowed: true }],
    ...Array(3).fill([429, {}, { "Retry-After": "0" }]), [429, {}, { "Retry-After": "300" }]);
  const started = performance.now();
  assert.equal(await client.screen("lookup", "", "low"), true);
  assert.ok(performance.now() - started >= 950);
  assert.equal(await client.screen("lookup", "", "low"), false);
  assert.equal(requests.length, 5);
  assert.equal(await client.screen("lookup", "", "low"), false);
  assert.equal(requests.length, 6);
});

test("starts, checks stop, finishes, and reports the complete run", async t => {
  const receipt = { ok: true, goal_id: 42 };
  const [client, requests] = await mock(t, [201, { ...receipt, heartbeat_seconds: 5 }],
    [200, { continue: true }], [200, { continue: false }], [200, receipt], [201, receipt]);
  assert.deepEqual(await client.startRun({ title: "Check item" }), { goalId: 42, heartbeatSeconds: 5 });
  assert.equal(await client.heartbeat(42), true);
  assert.equal(await client.heartbeat(42), false);
  assert.equal(await client.finishRun(42, result), 42);
  assert.equal(await client.reportRun({ title: "Check item", ...result }), 42);
  assert.deepEqual(requests.map(row => row[1]), [
    "/runs/start", "/runs/42/heartbeat", "/runs/42/heartbeat", "/runs/42/finish", "/runs",
  ].map(path => root + path));
  assert.deepEqual(requests[3][3], { ...result, tool_calls: 2 });
  assert.deepEqual(requests[4][3], { title: "Check item", ...result, tool_calls: 2 });
});
