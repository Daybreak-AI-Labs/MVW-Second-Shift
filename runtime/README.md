# Second Shift runtime

A small agent runtime for agents built by the Second Shift agent factory. The same code runs an agent in three places:
inside Second Shift (to test it before release), in an Azure container (Azure Container Apps), and in an Amazon Bedrock
AgentCore container. Microsoft Foundry Agent Service runs agents itself, so Foundry gets an agent definition, not this runtime.

Every run is governed by Second Shift. Before each action the runtime asks Second Shift, waits for a person when Second
Shift says one must approve, stops when Second Shift says stop, and reports each run. If Second Shift cannot be reached,
nothing runs.

The package depends on `httpx` only. It does not import `maverick` or `maverick_dashboard`; it talks to Second Shift over
HTTP.

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[office]'     # [office] adds the three document libraries
.venv/bin/python -m second_shift_runtime run --definition agent.json --input "Summarise https://example.com" --output ./files
.venv/bin/python -m second_shift_runtime serve --definition agent.json --port 8080
.venv/bin/python -m pytest -q tests                                  # from this folder
```

`run` prints the answer, writes any files the agent made into `--output`, and exits 0 on success, 1 when the run failed
(the reason is printed to standard error) and 2 when the definition cannot be used.

## The agent definition

One JSON document. Unknown fields are refused. Secrets are never in it: the model address, the model key, the Second
Shift address and the agent key are given as the **names** of environment variables.

```json
{
  "id": "research-helper",
  "name": "Research helper",
  "description": "Finds a page and writes a short Word summary.",
  "version": "1.0",
  "instructions": "You help staff research public web pages. Be brief and cite the page you used.",
  "model": {
    "provider": "foundry_openai",
    "endpoint_env": "FOUNDRY_ENDPOINT",
    "api_key_env": "FOUNDRY_API_KEY",
    "deployment": "my-gpt-deployment",
    "max_output_tokens": 2000,
    "input_price_per_million": 2.0,
    "output_price_per_million": 8.0
  },
  "skills": [
    {"name": "web_search", "settings": {"max_results": 5}},
    {"name": "fetch_web_page", "settings": {"max_text_chars": 20000}},
    {"name": "create_word_document", "risk": "medium"}
  ],
  "limits": {"max_steps": 10, "max_tool_calls": 20, "max_seconds": 300, "max_cost_dollars": 1.0, "max_input_chars": 20000},
  "governance": {"address_env": "SECOND_SHIFT_URL", "agent_key_env": "SECOND_SHIFT_AGENT_KEY"}
}
```

* `provider`: `foundry_openai` (OpenAI-compatible v1 API on a Foundry resource) or `foundry_anthropic` (Claude on Foundry).
* Prices are your own figures per million tokens; none are built in. Without prices there is no cost estimate (the report says
  so) and `max_cost_dollars` is refused, because it could not be checked.
* `risk` on a skill can raise its rating (`low` < `medium` < `high`), never lower it.
* Limits default to 10 steps, 20 tool calls, 300 seconds, 20000 input characters and no cost cap.
* `config_digest` is the SHA-256 of the canonical definition. It goes to Second Shift in the run report so a changed
  definition shows up as drift.

## How governance works

All calls go to `{SECOND_SHIFT_URL}/api/v1/external/...` with the agent key as a bearer token.

1. `POST /runs/start` opens a live run. The reply names the heartbeat interval.
2. A background heartbeat (`POST /runs/{id}/heartbeat`) runs at that interval, and one is also sent before each model call and
   each tool call. `continue: false` (the emergency stop, containment, revocation) stops the run at once.
3. Before **every** tool call the runtime calls `POST /screen` with the tool name, its risk rating and a short plain summary of
   the arguments (never the raw arguments; the web page skill leaves out the query string).
4. If the answer is `requires_approval`, the runtime polls `GET /approvals/{id}?binding_sha256=...` until a person approves
   or denies, or the wait (300 seconds) passes. A changed binding is not honoured.
5. `POST /runs/{id}/finish` reports outcome (`success` or `failure`), cost, token counts, `tools` (one name per call, no
   arguments) and `declared` (`version`, `config_digest`, `model`). The finish is always attempted, whatever went wrong.

It fails closed: an unreachable Second Shift, a refusal, a denial, an approval timeout, an unreadable answer or
`continue: false` means the tool does not run and the run stops, with a plain reason in the result and the report. A `429`
is retried up to three times, waiting as long as `Retry-After` says (at most 60 seconds). A run is not started at all when
`address_env` or `agent_key_env` is empty.

Tool results go back to the model as tool results (data), and the system prompt tells the model not to follow instructions
inside them. A tool error becomes a tool result; it does not crash the run.

## Skills

| Skill | What it does | Default risk |
| --- | --- | --- |
| `fetch_web_page` | GET one public http(s) page and return readable text. | low |
| `web_search` | Titles, addresses and snippets from a search provider. | low |
| `create_word_document` | `.docx` from a title and blocks (heading, paragraph, bullets, table). | low |
| `create_presentation` | `.pptx` from slides (title, bullets, notes). | low |
| `create_spreadsheet` | `.xlsx` from sheets of rows; text is never stored as a formula. | low |

`fetch_web_page` has its own guard because this package cannot use Second Shift's. It resolves the host and refuses the
request if any answer is a private, loopback, link-local, multicast or reserved address (IPv4 and IPv6; mapped, NAT64 and
6to4 forms are unwrapped and checked). It connects to the address it checked, with the original host name for the
certificate, checks every redirect again (at most 3), allows ports 80 and 443 only, no user name in the address, only
`text/html` and `text/plain`, and bounds size (default 1 MB) and time (default 15 seconds). It ignores proxy variables.
Settings: `max_bytes`, `max_text_chars`, `timeout_seconds`.

`web_search` uses the Brave Search API (the Bing Search APIs were retired on 11 August 2025). The key comes from the variable
named in `api_key_env` (default `BRAVE_SEARCH_API_KEY`). Settings: `provider`, `api_key_env`, `max_results` (1 to 20),
`timeout_seconds`. Another provider is one class with a `search(query, count, client)` method added to `PROVIDERS` in
`skills/search.py`.

The document skills write only into the run's output folder under generated names (the model never gives a path), with
bounded sizes (200 blocks, 50 slides, 10 sheets of up to 1000 rows, 5 MB per file). Each result lists the file's name, size
and SHA-256. They need the `office` extra (`python-docx`, `python-pptx`, `openpyxl`); without it the skill answers with a
clear message and everything else still works.

A new skill is a class in `skills/` with `name`, `description`, `input_schema`, `default_risk`, `describe(args)` (the plain
summary Second Shift sees) and `run(args, context)`, listed in `registry()`.

## Running in a container

`serve` listens on `0.0.0.0:8080` and implements the Amazon Bedrock AgentCore HTTP contract, which works unchanged in Azure
Container Apps (point the ingress and the health probe at port 8080 and `/ping`):

* `GET /ping` answers `{"status": "Healthy"}` (`HealthyBusy` while a run is in progress).
* `POST /invocations` takes `{"prompt": "..."}` and answers
  `{"response": "...", "status": "success" | "failure", "reason": "...", "files": [...], "usage": {...}}`. A governed refusal
  is a normal answer with `status: failure` and the reason. Files are returned inside the answer (base64) because a
  container's disk is not reachable. At most 4 runs at once (`429` with `Retry-After` beyond that).
* `--inbound-key-env NAME` makes `/invocations` require `Authorization: Bearer <value of NAME>`; `/ping` stays open for probes.

AgentCore needs an arm64 image; the repository does not build one.

## Environment variables

Names are chosen in the definition; these are the ones used in the examples.

| Variable | Used for |
| --- | --- |
| `FOUNDRY_ENDPOINT` (`model.endpoint_env`) | Base address of the model. `foundry_openai`: `https://<resource>.openai.azure.com/openai/v1` (or `.services.ai.azure.com/openai/v1`). `foundry_anthropic`: `https://<resource>.services.ai.azure.com/anthropic`. |
| `FOUNDRY_API_KEY` (`model.api_key_env`) | Model key (`api-key` header for OpenAI models, `x-api-key` for Claude). |
| `SECOND_SHIFT_URL` (`governance.address_env`) | Second Shift address, `https://...` (plain http only for localhost). |
| `SECOND_SHIFT_AGENT_KEY` (`governance.agent_key_env`) | The agent's key from Second Shift's external agents page. |
| `BRAVE_SEARCH_API_KEY` (`web_search` `api_key_env`) | Brave Search key. |
| `SECOND_SHIFT_LOG_LEVEL` | Log level (default `WARNING`). Keys and prompts are never logged. |

## What was not tested against real services

* No real model call was made, to either provider. Both clients are tested against recorded-shape fakes built from
  Microsoft's documentation. Newer OpenAI-family deployments take `max_completion_tokens`, which is what is sent; a deployment
  that only accepts `max_tokens` would need a one-line change in `models.py`.
* No real Brave Search call (the key and network were not available); the request and response follow Brave's documentation.
* No real web page was fetched and no TLS handshake was made. The pinned-address request is tested with a fake transport; the
  `sni_hostname` extension that carries the host name for certificate checking is httpcore behaviour that was not exercised
  against a real server.
* Not run in a real Azure Container Apps or AgentCore container; no container image is built here.
* Against Second Shift itself the flow was exercised once against a locally started dashboard (start, heartbeat, screen,
  approval wait and approval, finish, and the emergency stop) with a scripted model. That was a manual check, not a test in
  this folder.
