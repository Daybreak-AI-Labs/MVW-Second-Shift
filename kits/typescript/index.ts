export type Risk = "low" | "medium" | "high";
export interface RunStart {
  title: string;
  summary?: string;
  department?: string;
  /** Your build, told to Second Shift before the first action so drift knows it. */
  declared?: { version: string; config_digest: string; model: string };
}
export interface RunResult {
  outcome: "success" | "failure";
  cost_dollars: number;
  input_tokens: number;
  output_tokens: number;
  tools: readonly string[];
  declared: { version: string; config_digest: string; model: string };
  summary?: string;
  steps?: readonly string[];
  duration_seconds?: number;
  idempotency_key?: string;
}

type Json = Record<string, unknown>;
const requestTimeout = 10_000;
const retryBudget = 140_000;
const now = () => performance.now();
const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
const positiveId = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value > 0;

function retryDelay(header: string | null, attempt: number): number {
  if (header && /^\d+$/.test(header)) return Number(header) * 1_000;
  if (header) {
    const date = Date.parse(header);
    if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  }
  return 250 * 2 ** attempt;
}

export class SecondShiftClient {
  #origin: string;
  #key: string;

  constructor(baseUrl: string, accessKey: string) {
    const url = new URL(baseUrl);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
        url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
        !/^[A-Za-z0-9._~+\/=-]+$/.test(accessKey)) {
      throw new Error("A Second Shift origin and access key are required.");
    }
    this.#origin = url.origin;
    this.#key = accessKey;
  }

  async #request(path: string, body?: object, deadline = now() + retryBudget): Promise<Json> {
    try {
      for (let attempt = 0; attempt <= 2; attempt++) {
        const remaining = Math.floor(deadline - now());
        if (remaining < 1) break;
        const response = await fetch(this.#origin + "/api/v1/external" + path, {
          method: body === undefined ? "GET" : "POST",
          headers: {
            Authorization: "Bearer " + this.#key,
            ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          redirect: "error",
          signal: AbortSignal.timeout(Math.min(remaining, requestTimeout)),
        });
        const retryAfter = response.headers.get("Retry-After");
        const busy = response.status === 503 && retryAfter !== null
          && response.headers.get("X-Second-Shift-Admission") === "busy";
        if ((response.status === 429 || busy) && attempt < 2) {
          const delay = retryDelay(retryAfter, attempt);
          await response.body?.cancel();
          if (delay >= deadline - now()) break;
          await sleep(delay);
          continue;
        }
        if (!response.ok) {
          await response.body?.cancel();
          break;
        }
        const result: unknown = await response.json();
        if (now() < deadline && result && typeof result === "object" && !Array.isArray(result)) {
          return result as Json;
        }
        break;
      }
    } catch {
      // Transport and parser errors can contain request or response data.
    }
    throw new Error("Second Shift did not return a usable response.");
  }

  /** Returns true only for this proposal. Screen again before each action. */
  async screen(tool: string, detail: string, risk: Risk, approvalWaitMs = 60_000): Promise<boolean> {
    try {
      if (!["low", "medium", "high"].includes(risk)) return false;
      if (!Number.isFinite(approvalWaitMs) || approvalWaitMs < 0 || approvalWaitMs > 900_000) return false;
      const decision = await this.#request("/screen", { tool, detail, risk });
      if (decision.allowed === true) {
        return decision.requires_approval === undefined || decision.requires_approval === false;
      }
      if (decision.allowed !== false || decision.requires_approval !== true) return false;
      const id = decision.approval_id;
      const binding = decision.approval_binding_sha256;
      if (!positiveId(id) || typeof binding !== "string" || !/^[0-9a-f]{64}$/.test(binding)) return false;
      const deadline = now() + approvalWaitMs;
      while (now() < deadline) {
        const reply = await this.#request(
          `/approvals/${id}?binding_sha256=${binding}`, undefined, deadline,
        );
        if (reply.approval_id !== id || reply.approval_binding_sha256 !== binding ||
            typeof reply.expires_at !== "number" || !(reply.expires_at > Date.now() / 1000)) return false;
        if (reply.status === "approved") return true;
        if (reply.status !== "pending") return false;
        await sleep(Math.min(1_000, Math.max(0, deadline - now())));
      }
    } catch {
      // The caller may act only on an explicit true.
    }
    return false;
  }

  async startRun(run: RunStart): Promise<{ goalId: number; heartbeatSeconds: number }> {
    const reply = await this.#request("/runs/start", run);
    const interval = reply.heartbeat_seconds;
    if (reply.ok !== true || !positiveId(reply.goal_id) ||
        typeof interval !== "number" || !Number.isFinite(interval) || interval <= 0) {
      throw new Error("Second Shift did not confirm the run started.");
    }
    return { goalId: reply.goal_id, heartbeatSeconds: interval };
  }

  async heartbeat(goalId: number): Promise<boolean> {
    if (!positiveId(goalId)) return false;
    try {
      return (await this.#request(`/runs/${goalId}/heartbeat`, {}, now() + requestTimeout)).continue === true;
    } catch {
      return false;
    }
  }

  async finishRun(goalId: number, result: RunResult): Promise<number> {
    if (!positiveId(goalId)) throw new Error("A valid run identifier is required.");
    const reply = await this.#request(`/runs/${goalId}/finish`, this.#result(result));
    return this.#receipt(reply, goalId);
  }

  async reportRun(run: RunStart & RunResult): Promise<number> {
    return this.#receipt(await this.#request("/runs", this.#result(run)));
  }

  #result(result: RunResult) {
    return { ...result, tool_calls: result.tools.length };
  }

  #receipt(reply: Json, expected?: number): number {
    if (reply.ok !== true || !positiveId(reply.goal_id) ||
        (expected !== undefined && reply.goal_id !== expected)) {
      throw new Error("Second Shift did not confirm the run was recorded.");
    }
    return reply.goal_id;
  }
}
