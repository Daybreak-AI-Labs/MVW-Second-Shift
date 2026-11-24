# Models and model drift

Second Shift keeps a register of the AI models your agents use, and can tell
you when the data around a model no longer looks the way it did when you
approved it. This page says what is recorded, how the owner of a model sends
samples, what each statistic means, and what none of it can tell you.

Open **Models** (`/models`) to see the register. Anyone who can view Second
Shift can read it.

## The register

A model gets into the register in three ways:

- An agent reports the model it runs on in a run report (the `declared.model`
  field). If the value is not a plain name (for example a long text), Second
  Shift keeps only a digest of it in the agent's record and does not register
  it.
- A platform check finds the model in the agent's description on its platform
  (Microsoft Foundry today).
- An administrator adds it by hand: a name, a provider, what it is used for, an
  owner, a risk tier (unrated, low, medium or high) and the agents that use it.
  Use this for models no agent reports, such as a scoring model that a
  business application calls.

For each model the register keeps its agents (and how each was found), when it
was first and last seen, its owner and risk tier, and its monitoring status:
**No baseline yet**, **Baseline waiting for approval**, **Monitored**, or
**Changed from its baseline**. A model's name is its identity: two entries with
the same name in other letter case are one model. The register holds up to 500
models.

## What is recorded, and what never is

Second Shift receives no inputs or outputs from the platforms where models
run. The owner of a model sends samples; Second Shift evaluates each batch in
memory and drops it.

**Never recorded:** the samples themselves: no feature value, no individual
prediction, no true label, no embedding row. Nothing of a batch is written to
the database, a file, the audit log or a log line, and an error message never
repeats a value that was sent.

**Recorded**, and bounded:

- a *profile* of the baseline batch: for each numeric feature or score, its
  count, its average, and a histogram (the bin edges and how many samples fell
  in each bin; the edges run from the 1st to the 99th percentile of the batch);
  for each categorical feature or predicted class, how many samples fell in
  each named category; for embeddings, only their average (the centroid); and
  an accuracy, when true labels were sent;
- the *statistics* of each check (the numbers in the table below, not the
  samples) for the newest 30 checks, and the findings;
- who sent each batch and who approved each baseline, and an audit entry for
  each of those, each finding and each acknowledgement.

A category name is a value that was sent, so Second Shift only names a category
seen at least five times in the batch; rarer values are counted under "other".
At most 16 features and 32 category names per feature are kept. Do not send a
feature whose common values are themselves private (a name or an address); send
a derived feature instead.

Records live in the same store as other governed records: private files on a
single server, PostgreSQL when the installation uses it.

## Sending samples

Two kinds of batch use the same address:

- **A baseline batch** describes what normal looks like. It becomes a
  *candidate*; nothing is compared with it until an administrator approves it
  on the model's page (or with `POST /api/v1/models/{id}/baseline/approve`). A
  newer baseline batch replaces a waiting candidate.
- **A check batch** is compared with the approved baseline. Send one as often
  as your model's data changes: daily, or after each batch job.

A batch is a JSON object with these fields, all optional except `purpose`
(`"baseline"` or `"check"`); a field that is not listed is refused:

| Field | What it holds |
| --- | --- |
| `numeric` | feature name to a list of numbers |
| `categorical` | feature name to a list of short texts |
| `predictions` | the model's outputs: numbers (a score) or texts (a class) |
| `labels` | the true values, in the same order as `predictions`, when known |
| `embeddings` | a list of lists of numbers, all the same length |

Every series needs at least 30 values (a setting) and at most 5,000; a batch
holds at most 16 features, 200 embeddings of at most 256 numbers, and 20,000
numbers in all, and its body at most 256 KiB. A caller may send at most 20
batches a minute for one model (a setting). A check that carries a series the
baseline does not have leaves it out and says so in its answer; a check that
shares nothing with the baseline is refused.

Who may send: anyone with the `operate` permission, through
`POST /api/v1/models/{id}/samples`; and an outside agent, with the same access
key it uses to report runs, through
`POST /api/v1/external/models/{id}/samples`, but only for a model its agent is
listed as using. `GET /api/v1/external/models` lists the models an agent uses
and their ids. An agent's key opens nothing else here.

A short example for an agent's owner, using only `httpx` (set the address and
the agent's access key in the environment; never write the key in the code):

```python
import os
import random

import httpx

client = httpx.Client(
    base_url=os.environ["SECOND_SHIFT_URL"],
    headers={"Authorization": "Bearer " + os.environ["SECOND_SHIFT_AGENT_KEY"]},
    timeout=30,
)

# Which models does this agent use? (Use the id of the one you want.)
models = client.get("/api/v1/external/models").raise_for_status().json()["models"]
model = next(m for m in models if m["name"] == "claude-sonnet")

# Numbers from your own system; here, made up.
ages = [random.gauss(40, 8) for _ in range(500)]
scores = [random.random() for _ in range(500)]

reply = client.post(
    f"/api/v1/external/models/{model['id']}/samples",
    json={"purpose": "baseline", "numeric": {"customer_age": ages}, "predictions": scores},
)
reply.raise_for_status()
print(reply.json())  # a baseline waits until an administrator approves it
```

Later, send `"purpose": "check"` with the same feature and prediction names. The
answer lists the signals compared, any left out, and the findings, with
`new_findings` for the ones reported for the first time.

## The statistics, in plain words

Each compares the latest check batch with the approved baseline.

| Statistic | In plain words | Applies to |
| --- | --- | --- |
| Population stability index (PSI) | How much the share of samples in each bin has moved. 0 is no change. Practitioners treat about 0.1 as a small shift and 0.25 as a large one. A bin with under 0.01% of samples counts as 0.01%, so one stray sample in an empty bin does not make the number huge. | numeric, categorical, predictions |
| Jensen-Shannon divergence | A symmetric measure of how different two spreads are, from 0 (identical) to 1 (nothing in common), in bits. | numeric, categorical, predictions |
| Chi-squared two-sample test | The chance (a p-value) of seeing a difference this large if both batches came from the same spread. A small p-value says the spreads probably differ. | numeric, categorical, predictions |
| Kolmogorov-Smirnov test (binned) | The largest gap between the two cumulative distributions, with a p-value. It can only see differences between bins, not inside one. | numeric, numeric predictions |
| Embedding centroid cosine distance | The angle between the average embedding of the baseline and of the check: 0 for the same direction, 1 for unrelated, 2 for opposite. | embeddings |
| Accuracy decay | How far the share of correct predictions has fallen below the baseline's. Needs `labels` in both batches. | predictions with labels |

A whole-number prediction with ten or fewer distinct values (such as 0 and 1) is
counted as a class, not as a score.

## Thresholds, and why you must calibrate them

A finding is made when a statistic crosses its limit. The limits are settings in
the `[model_drift]` section of the configuration file. The defaults are only a
starting point:

| Setting | Default | A finding when |
| --- | --- | --- |
| `psi_threshold` | 0.2 | PSI is at or above it |
| `js_threshold` | 0.1 | Jensen-Shannon divergence (bits) is at or above it |
| `chi2_p_value_floor` | 0.01 | the chi-squared p-value is at or below it |
| `ks_p_value_floor` | 0.01 | the Kolmogorov-Smirnov p-value is at or below it |
| `embedding_cosine_threshold` | 0.1 | cosine distance is at or above it |
| `accuracy_decay_threshold` | 0.05 | accuracy has fallen by this much or more (0.05 is five points) |
| `bins` | 10 | the histogram bins for a numeric series (2 to 32) |
| `min_samples` | 30 | a series needs at least this many values (10 to 5,000) |
| `batches_per_minute` | 20 | the limit for one caller and one model |
| `enable` | true | `false` turns checks off; the register still works |

A finding is *medium*, or *high* when PSI, the divergence, the cosine distance
or the accuracy drop is at least twice its limit.

**Calibrate each model.** What counts as a big change depends on the model, the
data and the size of a batch. Two batches from the same unchanged source still
differ by chance: with 400 samples a PSI of 0.05 to 0.1 is ordinary noise. The
p-value tests react to batch size: with thousands of samples a difference too
small to matter gives a tiny p-value, and with a few dozen a real change may
not. Watch a model's checks (the chart on its page shows the largest PSI of
each) for a few weeks while you know nothing changed, and set limits above what
you see. Raise `min_samples` for noisy data.

## What happens when a check crosses a limit

Each finding is written to the audit trail once (`model_drift_detected`) and one
alert goes out for the findings a check reported for the first time. The
finding shows on the model's page, on the page of each agent that uses the
model, and in the "Agents behaving differently" section of Home. A finding that
is still there on the next check is not reported again unless it becomes more
severe.

Anyone who can respond to agents can **acknowledge** a finding on the model's
page. It stays listed, marked acknowledged, and stops counting; it is open
again if it gets worse, and an acknowledgement is dropped a day after the
finding stops appearing. Approving a new baseline clears the findings of the
old one.

Second Shift never pauses, blocks or limits an agent because of one of these
statistics. A person decides.

## What it cannot tell you

- That a model is wrong, biased or unsafe. It says the data looks different from
  your baseline, nothing more. A model can drift in ways these statistics do not
  see, and can be fine after a large shift.
- Anything about samples nobody sent. A model whose owner stops sending batches
  looks quiet, not safe. The page shows when the last check was.
- Whether the baseline was a good one. Approve a baseline from data you trust.
- Anything about the individual cases: only the spread of the data is compared.
- Which feature caused a change beyond the findings' names, or why it happened.
- That the batches are representative. A sample of 400 rows says little about a
  rare segment.
