# Agent factory

The agent factory lets a person describe an agent, have Second Shift draft it with a model, edit and test it, and release it after a second person approves. On release Second Shift enrolls the agent as an outside agent, so it is governed from its first action.

Open it at **Agent factory** (`/factory`). It needs the optional runtime package; without it the page says so and everything else works.

## Install

The factory uses the Second Shift runtime as a library, so there is one agent definition format. From a checkout, install the runtime first, then the extra is satisfied:

```bash
pip install -e './runtime[office]'
pip install -e '.[factory]'
```

## Settings (`[factory]`)

| Setting | Meaning | Default |
| --- | --- | --- |
| `provider` | `foundry_openai` or `foundry_anthropic` | none, required |
| `deployment` | Model deployment name | none, required |
| `endpoint_env`, `api_key_env` | The NAMES of the environment variables holding the model address and key | `SECOND_SHIFT_FACTORY_MODEL_ENDPOINT`, `SECOND_SHIFT_FACTORY_MODEL_KEY` |
| `max_output_tokens` | Most tokens per model answer | 2000 |
| `input_price_per_million`, `output_price_per_million` | Your own prices, for cost estimates. Without both, a test run is refused because its cost cannot be bounded | none |
| `max_test_cases` | Most test cases per agent (and per run) | 20 |
| `max_case_seconds` | Longest one test case may run | 120 |
| `max_test_run_seconds` | Longest a whole test run may take | 900 |
| `max_test_run_cost_dollars` | Most a whole test run may cost; a run estimated above it does not start | 2.0 |

A key is never stored in a setting, a record, a page or a log.

## Building an agent

1. **Draft.** Say what the agent is for, who uses it, what it may and must not do. The model proposes a name, description, instructions, skills (with their risk ratings) and limits. The proposal is checked with the runtime's schema; one that fails is shown with the reasons and is never saved. Nothing is saved until you choose Save as draft.
2. **Edit.** Every field is editable; skills are a checklist (a rating can be raised, never lowered). Each save is a new revision and any change makes the version untested again. The model section and the Second Shift section of the definition come from the settings.
3. **Test.** A test case is an input plus checks: must use a skill, must not use a skill, the answer must or must not contain a phrase, must produce a docx, pptx or xlsx file, must cost less than an amount. Run tests runs every case through the runtime with the configured model and a stand-in for Second Shift inside the server. The stand-in records every screen call and allows what the definition's own ratings allow. No outside agent is created and a test never counts as the agent's activity. Results show the checks, steps, tools used, cost and time.
4. **Release.** Submit for release is possible only when every case passed on that exact version. It creates an approval (provenance `factory_release`) on the Approvals page. The person who last changed the version, and the person who submitted it, cannot approve it. On approval the agent is enrolled with platform `custom`, its skills as allowed tools at their ratings, the longest run time from its limits as the wall-time limit, and the highest skill rating as the riskiest action allowed. The version becomes released and its `config_digest` becomes the approved configuration for drift checks. Releasing a new version updates the enrollment, retires the previous version, and refuses skills that were taken out. The per-run cost limit stays in the definition (the runtime enforces it); the monthly budget is still set on the Outside agents page.

Retiring a released agent needs the admin permission and removes its enrollment.

## Exporting a released agent

A released version has an **Export** section on its page (administrators only). It offers one package per place the agent can run. Each package holds the version's definition exactly as released (`agent.json`, whose digest is the `config_digest` the page shows), a copy of the runtime source, a container recipe, the deployment files and a README with the exact steps. **No package holds a secret.** A definition names environment variables; the deployment files name Key Vault or Secrets Manager secrets by name only.

| Target | What you get | What you need |
| --- | --- | --- |
| Azure container | `Dockerfile` (runtime installed with the document skills), `main.bicep` (one Container App with its own user-assigned managed identity, Key Vault references for the model key, the agent's Second Shift key, the search key and an inbound key, and `/ping` startup, liveness and readiness probes), `README.md` | A Container Apps environment, an RBAC Key Vault and a container registry in one resource group |
| AWS Bedrock AgentCore | An ARM64 `Dockerfile` that serves `GET /ping` and `POST /invocations` on port 8080, `entrypoint.py` (reads the named Secrets Manager secrets into the variables the definition names), `trust-policy.json`, `execution-policy.json`, `README.md` (ECR, role, `create-agent-runtime`, invoking) | An AWS account where AgentCore is available, Docker buildx, the AWS CLI |
| Microsoft Foundry | `foundry-agent.json` (a prompt agent on the model deployment with the definition's instructions and one OpenAPI tool that points at the skills service and uses a project connection), `skills-openapi.json`, `skills-service/` (the container recipe and Bicep for the skills service), `README.md` (project connection steps) | A Foundry project with a model deployment, and the skills service running in Azure |

### The agent's access key

The agent's Second Shift access key is made when you tick **Make a new access key** while exporting. It is shown once on the page with where to store it (the Key Vault or Secrets Manager secret the README names), is never written into a package, a record, an audit entry or a log, and **replaces the agent's earlier key, which stops working**. Leave the box unticked to download again without touching the key. If `[external_agents] mint_approval` is on, the export asks for the same step-up approval as any credential mint.

### Governing a Foundry agent: the skills service

Foundry runs a prompt agent itself, and has no step where Second Shift can check a tool call before Foundry makes it. So the agent's tools must be a service that does the checking. `python -m second_shift_runtime serve-skills --definition agent.json` (the same container image as the runtime) serves each skill as `POST /skills/<name>`, described by an OpenAPI 3.0 file that follows Foundry's documented rules for the OpenAPI tool (an `operationId` of letters, `-` and `_`, JSON request bodies, one API-key scheme with the key in a project connection, `x-api-key`). Every call is screened with Second Shift as the agent before the skill runs, waits for a person when Second Shift says one must approve (`--approval-wait-seconds`, default 60), obeys the emergency stop, and is reported. If Second Shift cannot be reached, nothing runs. A refusal is an HTTP error whose body carries the `kind` (`denied`, `approval_required`, `halted`, `contained`, `limit`, `unavailable`) and says whether to try again later.

Its own key (`SECOND_SHIFT_SKILLS_KEY` by default, change the name with `--inbound-key-env`) and the agent's key (the variable the definition names) come from environment variables by name.

**How calls become runs.** Foundry sends no conversation id to a tool, so the service cannot tell one conversation from the next. One run is open at a time: it opens at the first call, stays open while calls keep arriving, and is finished and reported after 120 quiet seconds (`--run-idle-seconds`), after the definition's `max_seconds`, or when Second Shift tells it to stop. The definition's `max_tool_calls` is the most calls in one run; a call beyond it is refused with kind `limit`. The report carries the tool names and the agent's build, and cost 0: the model runs inside Foundry, so its cost is not counted by Second Shift, and the step, time and cost limits of the definition are not enforced there.

**Anything else you add to the Foundry agent is not governed.** The agent should have no tool other than the skills service.

### Push to Foundry

Off unless an administrator sets `[factory.foundry] allow_push = true`. Second Shift then creates the prompt agent in the project named by `project_endpoint` (`https://<resource>.services.ai.azure.com/api/projects/<project>`) with its own credentials: `auth = "client_credentials"` with `tenant_id_env`, `client_id_env` and `client_secret_env` (names of environment variables), or `auth = "managed_identity"` (optionally `client_id_env` for a user-assigned identity; needs the `azure-identity` package). The button asks for the skills service address and the project connection id, and asks you to confirm by project and agent name. The request is administrator-only, audited before it is sent and after, sent once and never retried; if the audit log cannot take it, nothing is sent. On success the enrollment's platform link is set to `foundry:<resource>/<project>/<agent>`, the form the Foundry platform check reads, so a change made later in Foundry shows up as drift. A second released version can be added to the existing agent with "Add a version to the existing agent".

Pushing straight to Azure Container Apps or to AWS is not built in this version. Download the package and follow its README.

## Changes to the agent API

* A refusal from `/api/v1/external/screen` carries `kind`: `denied` (no; asking again will not change it), `approval_required` (a person must decide), `halted` (the emergency stop is on), `contained` (held for review), `limit` (a budget or backlog; try later) or `unavailable` (Second Shift could not decide; try later). An allowed answer has no `kind`. `rule` and `reason` are unchanged. A `429` from the gateway's own request limit is still an HTTP `429` with `Retry-After`, not a screening answer.
* `/api/v1/external/runs/start` accepts the optional `declared` build (`version`, `config_digest`, `model`) that run reports already take, so drift knows the build before the first action.

Both are optional and older agents are unaffected. The runtime, the connection file (`/api/v1/external/openapi.json`) and the TypeScript and .NET kits use them (the kits only gained the optional `declared` field on starting a run; they return a plain true or false for a screening and never parsed a refusal).

## Permissions

Reading needs `view`; drafting, editing, testing and submitting need `operate`; approving needs `approve`; retiring, exporting and pushing need `admin`. With a single signed-in person nothing can be released, by design.

## What was not tested

Nothing was run against a real model: drafting and test runs were exercised with scripted models and a local stand-in server.

**Exports were never run against a real Azure subscription, AWS account or Foundry project.** The packages were checked for shape, contents and secrets by tests; the Bicep was not compiled or deployed (no Azure CLI or Bicep was available), the Dockerfiles were not built, the AgentCore runtime was not created, and the Foundry request was tested only against a stand-in HTTP server. The OpenAPI file was checked against the rules Microsoft documents for the Foundry OpenAPI tool, not by Foundry. Not confirmed against Microsoft's documentation: the REST body of an OpenAPI tool inside an agent definition (shown there only for toolboxes and the SDK), the route for adding a version to an existing agent (shown for Foundry Local), how long Foundry waits for a tool call (so a long approval wait may time out), whether Foundry can reach a skills service on a private network, and the role the push needs. The Export page script was not run in a browser. The cost estimate before a run is rough and deliberately generous; the limit is enforced after each model call, so one call can overshoot.
