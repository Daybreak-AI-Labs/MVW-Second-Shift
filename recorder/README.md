# Second Shift recorder

One file, `second_shift_recorder.py`, that a person (or their IT team, for
them) runs on the person's own Windows or Mac computer. It is the part of Ekko
that notices which work apps are in front. Read `docs/ekko.md` first for what
Ekko is, consent, and what the server does with what the recorder hands over.

## What it does, and what it never does

Every few seconds the recorder asks the Second Shift server one question:
should I record now? Only when the answer is yes, because you pressed
**Start recording** on the Ekko page and have not paused or stopped, it
looks at which app is in front. If that app is one you allowed, it remembers
the switch and hands it over within about half a minute.

- It reads the program file name (Windows) or bundle identifier (Mac) of the
  app in front, and only to look it up in a short fixed list inside the file.
  An app that is not in the list is never named, kept or sent.
- It never reads a window title, the screen, the keyboard, the clipboard, a
  web address, a file name or anything inside a file.
- It never starts a session. Pause, stop and withdrawal on the page reach it
  at its next question, a few seconds later, and it drops whatever it had not
  yet handed over.
- It keeps nothing on disk: no activity file, no log file, no saved state. Up
  to 200 switches wait in memory. It writes short status lines to the
  terminal, never the key, an app name or an activity. (If you redirect its
  output to a file, that file holds only those status lines.)
- It talks only to the server in its settings file, over `https`, and does not
  follow redirects.

## What you need

- Python 3.11 or later.
- `pip install httpx`
- On a Mac also `pip install pyobjc-framework-Cocoa`.

Nothing else of Second Shift is installed on the computer.

## Settings file

On the Ekko page, enroll the computer, then choose **Create a recorder key**.
The page shows the key once, with the text of the settings file:

```json
{
  "server": "https://second-shift.example.com",
  "device_key": "ekr_..."
}
```

Save it as `.second-shift-recorder.json` in your home folder (or anywhere, and
pass `--config PATH`). The file holds a key, so only you may be able to read
it. The recorder checks this every time it starts and refuses a file other
users of the computer can read.

**Mac.** Create the file private before you paste the key into it:

```sh
install -m 600 /dev/null ~/.second-shift-recorder.json
```

then open it in an editor and paste the text. To fix an existing file:
`chmod 600 ~/.second-shift-recorder.json`.

**Windows.** A file in your own user folder (`%USERPROFILE%`) is normally
readable only by you, the system and administrators, and that is accepted. If
the recorder refuses the file, remove everyone else from it:

```bat
icacls "%USERPROFILE%\.second-shift-recorder.json" /inheritance:r /grant:r "%USERNAME%:F"
```

The server address must start with `https://`. Plain `http://` is accepted
only for a server on the same computer (`localhost`), for testing.

## Run it

```sh
python second_shift_recorder.py --check    # reads the settings file, asks the server once, records nothing
python second_shift_recorder.py            # runs until you press Ctrl+C
```

Run it as yourself, in your own desktop session: it can only see the app in
front of the person it runs as, and the server ties the key to that account.
To start it when you sign in, use a Task Scheduler task set to "Run only when
user is logged on" (Windows) or a LaunchAgent (Mac). Do not run it as a system
service.

It stops by itself, with a plain message, when the key is no longer accepted:

| Exit code | Meaning |
| --- | --- |
| 0 | You stopped it. |
| 2 | The settings file is missing, not private or not in the expected form, or this computer cannot be observed. |
| 3 | The server no longer accepts the key: consent was withdrawn or ended, or the key was replaced. Create a new key on the Ekko page. |
| 4 | The key was first used from a different computer account. Create a new key for this computer. |

If the server cannot be reached it records nothing, waits, and tries again
with longer and longer gaps (up to five minutes). A hand-over that fails is
tried again with the same id, so the server stores it once; one that still
cannot be delivered after five minutes is dropped.

## What was run, and what was not

This recorder was written and tested on Linux. Be clear about what that does
and does not show.

**Run** (`tests/new/test_ekko_recorder.py`):

- The whole loop, with a stand-in for "the app in front": asking, recording
  only when told to, obeying pause, stop and withdrawal at the next question,
  dropping apps that were not allowed, small batches, retry with the same id,
  backing off, stopping cleanly, never logging the key or an app name, and
  never opening a file for writing.
- The same loop against the real Second Shift server running in the test
  process (no real network).
- The settings-file check on Linux: a file others can read, a link and a
  missing file are refused. Mac uses the same rule (file owner and mode).
- The decision the Windows check makes, on sample access lists written by
  hand.
- That the fixed app lists, the switch logic and the account rule are the same
  as the server's own copies.

**Not run:**

- Anything on real Windows: reading the program in front
  (`GetForegroundWindow`, `QueryFullProcessImageNameW`), reading who may read
  the settings file (`GetNamedSecurityInfoW`), reading the account name
  (`GetUserNameExW`).
- Anything on a real Mac: reading the app in front through `NSWorkspace`. One
  line here differs from the server's copy of that reader: the recorder lets
  the system's run loop turn for a moment before each look, because a program
  that never does is known to keep seeing the app that was in front when it
  started. That line has not been tried on a Mac.
- A real network: TLS, a company proxy, a slow or dropped connection.
- Starting at sign-in, running for days, sleep and wake, fast user switching,
  remote desktop sessions.
- Packaging as a single program.

Before anyone is recorded, try it on one test computer of each kind: run
`--check`, start a session, switch between two allowed apps and one that is
not allowed, and confirm on the Ekko page that only the allowed ones are
counted, and that pause stops the count within a few seconds. On a Mac,
confirm that macOS does not ask for Accessibility or Screen Recording
permission; the recorder needs neither.

## Why it is a separate file

The file imports only the Python standard library and `httpx` (and, on a Mac,
`objc`, `AppKit` and `Foundation` from `pyobjc-framework-Cocoa`). It does not
use the server's own code on purpose: that would put the whole server, its
database and its dependencies on a person's computer, and run its start-up
code there. The recorder instead carries its own copies of the two fixed app
lists, the two small readers and the account rule, and a test fails if they
drift from the server's.
