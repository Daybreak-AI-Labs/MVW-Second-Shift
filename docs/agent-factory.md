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

## Permissions

Reading needs `view`; drafting, editing, testing and submitting need `operate`; approving needs `approve`; retiring needs `admin`. With a single signed-in person nothing can be released, by design.

## Not built yet

Exports to Azure, AWS and Microsoft Foundry, and access keys for released agents (they are made in the export step). A released version keeps its definition and `config_digest` for them.

## What was not tested

Nothing was run against a real model: drafting and test runs were exercised with scripted models and a local stand-in server. The cost estimate before a run is rough and deliberately generous; the limit is enforced after each model call, so one call can overshoot.
