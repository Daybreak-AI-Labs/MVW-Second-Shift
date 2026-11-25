# Work for Codex on Second Shift, round 4: sized for MVW

Follow "Working without Claude" in `handoff/codex-round-3.md` (merging, the review queue, the
rules). Finish round 3 job 7 (locked settings) before starting here. One pull request per job,
in this order.

**MVW's size:** about 20,000 workers, of whom about 2,000 are knowledge workers. Everyone may sign
in; the 2,000 knowledge workers use Second Shift regularly and are the people who would run the
Ekko recorder. It stays one copy of the app (one Container App replica) for everyone.

**Where it stands** (your load check, `docs/deploy-azure.md` "Local load check"): one app process
uses about one CPU core and pages slow down with the number of people arriving together (home
page median 7.6 s at 50, 26 s at 200, 81 s at 1,000). The Azure kit gives the container 0.5 CPU
and 1 GiB. That is not usable for 2,000 people.

---

## 1. Make each request cheaper

Branch `codex/request-cost`. Profile the load check (cProfile or py-spy) for Home, Outside
agents, Approvals, the agent screen and run report, and a Teams card action. Fix the largest
costs first: repeated reads or decryption of the same record within one request, work recomputed
on every page that could be computed once per request, one query per row where one query would
do. Report the before/after numbers per page.

A cache may only hold data whose staleness cannot widen access: never cache roles, revocations,
containment, the emergency stop, approvals or the replay ledger across requests. Tests first for
any cache, including one that proves a change made by another process is seen on the next
request.

## 2. Use more than one CPU core in the one copy

Branch `codex/worker-processes`. Run the app as several worker processes inside the one
container. Before you do:

- read `maverick_dashboard/app.py` `_lifespan` and `maverick/control_plane_lease.py`. The
  background jobs (drift checks, platform checks, reminders, owner notes, ServiceNow delivery and
  any others there) must run in exactly one worker at a time, and another worker takes over if
  that one stops. Prove it with a test that starts two processes;
- every in-process lock that protects shared state must be backed by a lock that works across
  processes (`maverick.record_documents` locks already do);
- the agent gateway's admission limits become per worker: keep the total the same and document it.

Set the worker count and the Container App's CPU and memory in the Bicep kit from the load
results (use a CPU and memory pair Container Apps allows, and cite the page). Add this job to the
review queue.

## 3. Browser sessions and Ekko's stores in PostgreSQL

Branch `codex/sqlite-stores-to-postgres`. With several worker processes and 2,000 Ekko recorders,
the three SQLite stores in the data folder (browser sessions
`maverick_dashboard/session_registry.py`, Ekko device keys `maverick/ekko_device_keys.py`, Ekko
work discovery `maverick/work_discovery_store.py`) would have several writers on Azure Files. When
the main database is PostgreSQL, keep them in PostgreSQL tables with the same tenant scoping and
row-level security as the rest; keep SQLite when it is not. Same checks, limits and refusals in
both modes; tests in both modes. Add to the review queue.

## 4. Per-person records for 20,000 people

Branch `codex/per-person-records`. The account names (`account_profiles.py`), sign-in subjects
(`subject_directory.py`), Teams links (`teams_identity.py`) and signed-out sessions
(`session_revocation.py`) are each one document rewritten whole on every change, under one lock.
At MVW's size that is a multi-megabyte rewrite per sign-in, and two limits may be reached:
the subject directory refuses above 4 MiB (`_MAX_STORE_CHARS`), and Teams links stop at 5,000
(`MAX_LINKS`). First measure the size per person and say at how many people each limit is hit.
Then, with PostgreSQL, keep one row per person (a keyed companion to `maverick.record_documents`:
same file/PostgreSQL split, same fail-closed rules, same encryption where the file was sealed),
and size the limits for at least 50,000 people. Test with 25,000 synthetic people: a sign-in costs
the same with 25,000 people as with 25. Add to the review queue.

## 5. Load check at MVW's size

Branch `codex/load-check-mvw`. Extend `tools/load_check.py` with Ekko recorders handing over
(read `docs/ekko.md` for how often a recorder hands over) and with 20,000 people already present
in the per-person records. Run it after jobs 1–4, with the CPU and memory the kit now sets, for:
200 and 500 people arriving together out of 2,000, 2,000 recorders handing over across one hour,
and 25 and 100 agents. Aim for: pages under 3 s at the 95th percentile with 200 arriving
together; no failed page or Teams requests; agent "busy" answers only above the admission limit,
and retried successfully by the kits. Say what limits first. From the results, set the kit's
worker count, CPU, memory, database pool size and PostgreSQL size, and replace the numbers in
`docs/deploy-azure.md`.
