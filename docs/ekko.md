# Ekko: finding repeated work

Ekko helps a person find work they repeat, so they can decide whether it is
worth automating. With that person's consent, a small recorder on their own
computer notices which work apps they switch between. The Second Shift server
looks for the same run of apps on different days and shows the person what it
found.

This page is for two readers: the administrator who turns Ekko on, and the
person who is recorded. Both should read the first three sections.

Ekko is off until an administrator turns it on, and records nobody until that
person enrolls their own computer and presses Start.

## 1. What is recorded, and what never is

**Recorded**, while a session is running, each time the person switches to an
allowed app:

- the app's name from a short fixed list (for example `excel`, `chrome`);
- when the switch happened;
- how long the app before it was in front.

That is all. There is no field for anything else: the server refuses a
hand-over that carries an unknown field or an app name that is not in the
list, so nothing more can be added by a changed or faulty recorder.

**Never recorded:** window titles, the screen, keystrokes, the clipboard, web
addresses, file names, or anything inside a file, email, message or record.
An app that is not in the fixed list is never named anywhere, not even on the
person's own computer.

**Never recordable:** email, chat, customer-record and business-system apps
(Outlook, Gmail, Teams, Slack, Salesforce, SAP and similar). They are blocked
in the product and cannot be allowed in the settings.

The recorder recognises these programs:

| Computer | Recognised as |
| --- | --- |
| Windows | `chrome`, `edge`, `firefox`, `excel`, `powerpoint`, `word`, `file_explorer`, `power_bi`, `tableau` |
| Mac | `chrome`, `edge`, `firefox`, `safari`, `excel`, `powerpoint`, `word`, `finder` |

## 2. Consent and withdrawal

Only the person can give consent, and only for themselves, on the **Ekko**
page (`/ekko`). Nobody can enroll someone else's computer.

1. The page says what is recorded and never recorded, before it asks anything.
2. The person names their computer, chooses apps from the ones the
   administrator allowed, chooses how long the consent lasts (7 to 90 days),
   ticks the box and enrolls. Enrolling records consent. It does not start
   recording.
3. The person creates a recorder key and puts it into the recorder on that
   computer (section 3).
4. The person presses **Start recording**. Only the person starts a session.
   The recorder cannot.

At any time, on the same page, the person can:

- **Pause** or **Stop**. The recorder asks the server what to do every few
  seconds (the poll interval, 5 seconds unless changed) and stops noticing
  apps at its next question. Whatever the recorder does, the server refuses
  activities for a session that is not running.
- **Withdraw consent.** Recording stops at once, and the recorder key ends.
  What was already recorded stays until the person erases it.
- **Erase** one recording, or everything recorded on that computer.
- **Forget this computer.** This erases everything, withdraws consent and ends
  the key.

Consent also ends by itself on the date chosen at enrollment, and it stops
being usable if the administrator narrows the allowed apps or changes the
recording settings: the person then has to enroll again, and decide again.

The person can also simply close the recorder on their own computer.

## 3. The recorder and its key

The recorder is one Python file, `recorder/second_shift_recorder.py`. Its own
instructions are in `recorder/README.md`. It runs on the person's computer, as
that person, and talks only to the Second Shift server.

### The key

A person who has enrolled a computer creates a **recorder key** for it on the
Ekko page. It is shown once. The server keeps only a hash of it.

The key is bound to the workspace, the person, the computer's name and the
exact enrollment it was created under. It ends when that enrollment ends, is
withdrawn or is replaced by a new enrollment, when the computer is forgotten,
when the person removes it, and when the person creates another one. A
computer has one working key at a time. Creating and removing a key is written
to the audit record.

A key can do exactly two things, for its own computer only:

1. **Read instructions:** whether Ekko is on, whether the enrollment is
   current, whether the session is running, paused, stopped or absent, which
   apps are allowed, and how often to ask.
2. **Hand over activities** for that computer's running session.

It cannot read anything that was recorded, any suggestion or any plan. It
cannot start, pause or stop a session. It is not a sign-in: every other
address in the product refuses it. In the other direction, a signed-in browser
session is not accepted on these two addresses.

If a key is copied or lost, the person removes or replaces it on the page.
Someone holding a stolen key could, until then, add app-switch activities to
that person's running session, with times no more than ten minutes off (see
section 5). They could read the instructions above and nothing else.

### Which computer account the key is used from

The first hand-over records a fingerprint of the operating-system account the
recorder runs as. A later hand-over from a different account is refused and
written to the audit record. To move a recorder to another account or
computer, create a new key.

What this does: it catches a key file that was copied to another Windows
account or another person's profile and used with an ordinary recorder.

What this does not prove: the fingerprint is something the recorder says about
itself. A person who has the key and writes their own program can send the
same fingerprint. On a Mac the account is its numeric user number, which is
often the same (501) for the first user of every Mac, so a move from one Mac
to another usually goes unnoticed. The server receives only the fingerprint,
never the account name.

## 4. Settings (administrator)

Ekko is set up in `config.toml`. It is turned on and off there, not from a
page.

```toml
[ekko]
enable = true                         # or set SECOND_SHIFT_EKKO=1; off by default
allowed_apps = ["excel", "powerpoint", "word", "chrome", "edge"]
retention_days = 14                   # each activity is deleted after this many days (2 to 30)
enrollment_days = 30                  # the length of consent the page suggests (1 to 90)
poll_interval_seconds = 5             # how often a recorder asks what to do (1 to 300)
min_occurrences = 3                   # repeats needed before something is suggested
min_distinct_days = 2                 # ...on at least this many different days
```

- **`allowed_apps`** is the most a person may choose from. An empty list means
  nobody can enroll. A person may choose fewer apps, never more.
- **Blocked apps.** `blocked_apps` can add to the built-in block list, never
  take away from it.
- **Changing these settings stops current enrollments.** Narrowing
  `allowed_apps` below what a person chose, or changing `blocked_apps`,
  `retention_days`, `poll_interval_seconds`, `min_occurrences`,
  `min_distinct_days` or `capture_level`, stops their recorder until they
  enroll again. This is deliberate: consent was given for the settings as
  they were.
- **`capture_level = "guided"`** lets an uploaded activity file say more than
  app switches. It does not widen what a recorder may hand over: the recorder
  path accepts app switches only.
- **Emergency stop.** While everything is stopped, no hand-over is accepted and
  recorders are told not to record.
- **Roles.** The page and its calls need the `operate` permission. There is no
  administrator view of anyone's recordings.

## 5. What the server checks on every hand-over

A recorder's word is never taken for anything. Each hand-over is checked
again, in this order, and nothing is stored unless every check passes:

1. The key is valid, its enrollment is still the one it was created under and
   has not ended, and its workspace is unchanged.
2. The settings can be read, Ekko is on, and the enrollment is still inside
   the administrator's limits.
3. Everything is not stopped.
4. The computer account matches the first one.
5. The session it names is that computer's session and is running.
6. When the recorder attaches to a session, a "start authorized" entry is
   written to the audit record first. If it cannot be written, nothing is
   accepted.
7. Each activity is an app switch for an app in the person's enrollment.
   Anything else is dropped and counted, never stored.

A hand-over carries an id, so one that is sent twice is stored once. A
hand-over may hold at most 50 activities and 16 KiB, and a key may hand over
60 times and ask for instructions 120 times a minute.

**Times.** The recorder says when each switch happened. The server keeps that
time only if it is believable by the server's own clock: not in the future,
not more than ten minutes old, not before the session started, and not before
the activity stored just before it. A time outside that range is moved to the
nearest edge of it. Suggestions depend on the same work being seen on
different days, so this rule means that neither a wrong laptop clock nor a
misused key can place an activity on another day.

If a key record, the settings or the enrollment cannot be read, the answer is
"nothing was accepted". There is no fallback.

## 6. Retention and erasure

- Each activity stops being readable `retention_days` after it happened, and
  is removed from the file the next time that person's recordings are read or
  written.
- The person can erase one recording, or everything on a computer, at any
  time. Erased data is overwritten in the database file.
- Withdrawing consent keeps what was recorded until the person erases it;
  **Forget this computer** does both at once.
- The recorder keeps nothing on disk. Activities wait in its memory (a few
  hundred at most, normally for under a minute) and are dropped the moment the
  server says recording is not running.
- The recorder key's record (a hash, and the sealed binding described above)
  is removed when the key is removed or replaced, when the person withdraws on
  the page, or otherwise the next time the recorder calls or the person opens
  the page after the enrollment has ended.

## 7. Who can see what

- **The person:** their own consent, sessions, activity count, suggestions and
  plans, on the Ekko page. Suggestions are patterns to investigate. They are
  never an employee performance score.
- **Other people, including managers and administrators:** nothing, in the
  product. Every read is tied to the signed-in person. There is no view across
  people and no export.
- **The audit record:** that consent was given or withdrawn, a key was created
  or removed, a recorder attached, a session started, paused or stopped, a
  hand-over from another account was refused, and data was erased, with times
  and session ids. Never an app name or an activity.
- **Whoever operates the server:** recordings are stored encrypted in the
  server's data folder. Someone with access to both that folder and the
  server's encryption keys could read them outside the product. Limit that
  access as you would for any personal data.

Ekko records that a named person used named apps at named times. That is
personal data about an employee. Before turning it on, decide the purpose,
tell the people concerned, and check what your local employment and privacy
rules require (in many places, consulting employee representatives).

## 8. Limits

- **Not run on real Windows or macOS.** The recorder's loop, its settings-file
  check and its hand-overs were tested on Linux with a stand-in for the
  computer's front app. The Windows and Mac readers, the Windows check of who
  can read the settings file, and a real network connection were not
  exercised. Try the recorder on one test computer of each kind before giving
  it to anyone. `recorder/README.md` lists exactly what was and was not run.
- **One server process.** The per-minute limits are counted inside each server
  process. Enrollment and key records are files in the data folder. Run one
  instance of the app, on storage that persists.
- **A person who can no longer sign in** cannot pause from the page. Their
  enrollment still ends on its date, they can close the recorder, and an
  administrator can turn Ekko off.
- **A recording holds at most 10,000 activities.** After that the server asks
  for a new one: stop and start again on the page.
- **App names only.** Ekko cannot tell what someone was working on, whether it
  saw the whole task, or how much time automation would save.
