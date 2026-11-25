"""The recorder program a person runs on their own computer (``recorder/second_shift_recorder.py``).

Run on Linux, where neither real observer exists: the loop is driven with a
stand-in observer that answers from a script of app names, and either the real
app in this process or a stand-in server. Nothing here opens a real desktop or
a real network connection.
"""
from __future__ import annotations

import ast
import builtins
import hashlib
import importlib.util
import json
import logging
import os
import stat
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

RECORDER_FILE = Path(__file__).resolve().parents[2] / "recorder" / "second_shift_recorder.py"
KEY = "ekr_0123456789abcdef_" + "k" * 43  # pragma: allowlist secret
SERVER = "https://second-shift.example.test"
ACCOUNT = "c" * 64


@pytest.fixture(scope="module")
def recorder_module():
    spec = importlib.util.spec_from_file_location("second_shift_recorder", RECORDER_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Desktop:
    """A stand-in for the computer: the app in front is whatever the test says."""

    def __init__(self, front: str | None = None):
        self.front = front
        self.looks = 0
        self.observers = 0

    def factory(self, module):
        def resolve():
            self.looks += 1
            return self.front

        def make():
            self.observers += 1
            return module.ForegroundObserver(resolve, clock=lambda: 0.0)

        return make


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


# --- the settings file -------------------------------------------------------------

def _settings_file(tmp_path, body=None, mode=0o600) -> Path:
    path = tmp_path / "recorder.json"
    path.write_text(json.dumps({"server": SERVER, "device_key": KEY} if body is None else body), encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.mark.skipif(os.name == "nt", reason="file modes are the POSIX rule; Windows uses access lists")
def test_a_settings_file_other_users_can_read_is_refused(recorder_module, tmp_path):
    assert recorder_module.read_settings(_settings_file(tmp_path)) == (SERVER, KEY)
    for mode in (0o640, 0o604, 0o644, 0o660, 0o666, 0o610):
        with pytest.raises(recorder_module.RecorderError) as refused:
            recorder_module.read_settings(_settings_file(tmp_path, mode=mode))
        assert "can be read by other users" in str(refused.value) and KEY not in str(refused.value)
    # A link is refused whatever it points at.
    target = _settings_file(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(recorder_module.RecorderError):
        recorder_module.read_settings(link)
    with pytest.raises(recorder_module.RecorderError):
        recorder_module.read_settings(tmp_path / "missing.json")


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="needs to create a file owned by another account")
def test_a_settings_file_owned_by_someone_else_is_refused(recorder_module, tmp_path):
    path = _settings_file(tmp_path)
    os.chown(path, 12345, 12345)
    with pytest.raises(recorder_module.RecorderError):
        recorder_module.read_settings(path)


def test_the_settings_file_must_hold_an_https_address_and_a_key(recorder_module, tmp_path):
    def refused(body) -> str:
        with pytest.raises(recorder_module.RecorderError) as error:
            recorder_module.read_settings(_settings_file(tmp_path, body))
        assert KEY not in str(error.value)
        return str(error.value)

    assert "must start with https://" in refused({"server": "http://second-shift.example.test", "device_key": KEY})
    for server in ("ftp://second-shift.example.test", "second-shift.example.test", "https://", "", 7,
                   "https://user:pw@second-shift.example.test", "https://second-shift.example.test/?next=x"):
        refused({"server": server, "device_key": KEY})
    for key in ("", " " + KEY, KEY + "\n", "two words", None, 7):
        refused({"server": SERVER, "device_key": key})
    refused({"server": SERVER, "device_key": KEY, "log_file": "/tmp/activity.log"})
    refused({"server": SERVER})
    refused([SERVER, KEY])
    path = _settings_file(tmp_path)
    path.write_text("{not json " + KEY, encoding="utf-8")
    with pytest.raises(recorder_module.RecorderError) as error:
        recorder_module.read_settings(path)
    assert KEY not in str(error.value)
    # A server on this same computer may be plain http; a trailing slash is dropped.
    local = _settings_file(tmp_path, {"server": "http://127.0.0.1:8000/", "device_key": KEY})
    assert recorder_module.read_settings(local) == ("http://127.0.0.1:8000", KEY)


def test_a_windows_access_list_must_name_only_the_user(recorder_module):
    private = recorder_module.acl_is_private
    me, other = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
    assert private(f"D:(A;;FA;;;{me})", me, me)
    assert private(f"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{me})", me, me)            # the system and administrators
    assert private(f"D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{me})", me, me)       # inherited from the home folder
    assert private(f"D:(A;;FA;;;OW)(D;;FA;;;WD)(A;;FA;;;{me})", "S-1-5-32-544", me)   # a deny entry only removes access
    assert not private(f"D:(A;;FA;;;{me})(A;;FR;;;BU)", me, me)                       # all users of the computer
    assert not private(f"D:(A;;FA;;;{me})(A;;FR;;;WD)", me, me)                       # everyone
    assert not private(f"D:(A;;FA;;;{me})(A;;FR;;;AU)", me, me)                       # anyone signed in
    assert not private(f"D:(A;;FA;;;{me})(A;;FR;;;{other})", me, me)                  # a named colleague
    assert not private(f"D:(A;;FA;;;{me})", other, me)                                # someone else's file
    assert not private("D:NO_ACCESS_CONTROL", me, me)                                 # no list: open to all
    assert not private("D:", me, me)
    assert not private(f"D:(XA;;FA;;;{me};(x))", me, me)                              # a kind it does not know
    assert not private(f"O:{me}", me, me)


# --- only what it needs --------------------------------------------------------------

def test_the_recorder_imports_only_the_standard_library_and_httpx():
    source = RECORDER_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add((node.module or "").split(".")[0])
    outside = imported - set(sys.stdlib_module_names)
    assert outside == {"httpx", "objc", "AppKit", "Foundation"}  # the last three: the Mac's own, loaded only on a Mac
    # Nothing of the server, nothing that stores, and nothing that reads more of the desktop.
    assert not imported & {"maverick", "maverick_dashboard", "sqlite3", "shelve", "pickle", "tempfile", "subprocess",
                           "shutil", "tkinter", "Quartz", "pyautogui", "pynput"}
    for never in ("GetWindowText", "GetClipboardData", "CGWindowListCopyWindowInfo", "AXUIElement", "localizedName",
                  "FileHandler", "shell=True"):
        assert never not in source, never
    # The only file it opens is its settings file, to read.
    writers = {"write", "write_text", "write_bytes", "writelines", "mkdir", "touch", "rename", "replace", "unlink", "dump"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = node.func
        assert not (isinstance(called, ast.Name) and called.id == "open"), ast.unparse(node)
        if isinstance(called, ast.Attribute):
            assert called.attr not in writers, ast.unparse(node)
            if called.attr in {"open", "fdopen"}:
                text = ast.unparse(node)
                assert ("O_RDONLY" in text or "'r'" in text) and not any(
                    flag in text for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "'w'", "'a'")), text


def test_the_copied_lists_and_readers_match_the_server_s_own(recorder_module, monkeypatch):
    from maverick import ekko_daemon, ekko_foreground, work_discovery
    from maverick.work_discovery_identity import local_os_principal

    assert recorder_module.WINDOWS_EXECUTABLE_APPS == ekko_daemon.WINDOWS_EXECUTABLE_APPS
    assert recorder_module.MACOS_BUNDLE_APPS == ekko_foreground.MACOS_BUNDLE_APPS
    assert recorder_module.KNOWN_APPS <= work_discovery.KNOWN_APPS
    assert recorder_module._os_account() == local_os_principal()
    assert recorder_module.account_fingerprint() == hashlib.sha256(
        ("second-shift-recorder-account:v1:" + local_os_principal()).encode()).hexdigest()
    assert recorder_module.INSTRUCTIONS_PATH == "/api/v1/external/ekko/instructions"

    def switches(observer, count):
        seen = []
        for _ in range(count):
            answer = observer.observe()
            seen.append((answer.app, answer.duration_seconds) if hasattr(answer, "app") else answer)
        return seen

    def ticking():
        ticks = iter(range(0, 1000, 7))
        return lambda: float(next(ticks))

    # The same apps in front give the same switches as the server's own observers.
    on_a_mac = ["excel", "excel", None, "excel", "safari", "secret-tool", "safari", "finder", "finder", "excel"]
    mine = recorder_module.ForegroundObserver(iter(on_a_mac).__next__, ticking())
    theirs = ekko_foreground.MacOSForegroundObserver(resolver=iter(on_a_mac).__next__, clock=ticking())
    assert switches(mine, len(on_a_mac)) == switches(theirs, len(on_a_mac))

    on_windows = ["excel.exe", "EXCEL.EXE", None, "C:\\Program Files\\Office\\WINWORD.EXE", "payroll-secret.exe",
                  "winword.exe", "explorer.exe", "notepad.exe", "", "chrome.exe"]
    theirs = ekko_daemon.WindowsForegroundObserver(resolver=iter(on_windows).__next__, clock=ticking())
    monkeypatch.setattr(recorder_module, "_windows_foreground_executable", iter(on_windows).__next__)
    mine = recorder_module.ForegroundObserver(recorder_module._windows_foreground_app, ticking())
    seen = switches(mine, len(on_windows))
    assert seen == switches(theirs, len(on_windows))
    assert [answer[0] for answer in seen if answer] == ["excel", "word", "word", "file_explorer", "chrome"]
    assert all(answer is None or answer[0] in recorder_module.KNOWN_APPS for answer in seen)


@pytest.mark.skipif(sys.platform in ("win32", "darwin"), reason="this computer has a real observer")
def test_a_computer_it_cannot_observe_is_said_plainly(recorder_module, tmp_path, caplog):
    with pytest.raises(recorder_module.RecorderError, match="Windows and macOS"):
        recorder_module.platform_observer()
    caplog.set_level(logging.INFO)
    assert recorder_module.main(["--config", str(_settings_file(tmp_path))]) == recorder_module.EXIT_SETTINGS
    assert "Windows and macOS" in caplog.text and KEY not in caplog.text


def test_a_settings_file_that_is_not_private_stops_the_program(recorder_module, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    code = recorder_module.main(["--config", str(_settings_file(tmp_path, mode=0o644)), "--check"])
    assert code == recorder_module.EXIT_SETTINGS
    assert "can be read by other users" in caplog.text and KEY not in caplog.text and "Traceback" not in caplog.text


# --- the loop, against a stand-in server ------------------------------------------------

class Server:
    """A stand-in server: answers from what the test sets, and keeps what it was sent."""

    def __init__(self):
        self.instructions: object = {"record": False, "reason": "session_none", "session": {"state": "none", "id": None},
                                     "allowed_apps": ["excel", "powerpoint"], "poll_interval_seconds": 5, "batch_limit": 50}
        self.handover: object = 200
        self.requests: list[httpx.Request] = []
        self.batches: list[dict] = []

    def record(self, session="ekko-session-0001", **more):
        self.instructions = {"record": True, "reason": "recording", "session": {"state": "running", "id": session},
                             "allowed_apps": ["excel", "powerpoint"], "poll_interval_seconds": 5, "batch_limit": 50, **more}

    def wait(self, reason="session_paused"):
        self.instructions = {"record": False, "reason": reason, "session": {"state": "paused", "id": None},
                             "allowed_apps": [], "poll_interval_seconds": 5, "batch_limit": 50}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.instructions if request.method == "GET" else self.handover
        if isinstance(answer, Exception):
            raise answer
        if request.method == "GET":
            return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json=answer)
        self.batches.append(json.loads(request.content))
        if isinstance(answer, httpx.Response):
            return answer
        if answer == 200:
            return httpx.Response(200, json={"accepted": len(self.batches[-1]["activities"]), "dropped": 0,
                                             "duplicates": 0, "times_adjusted": 0})
        return httpx.Response(answer, json={"detail": {"code": "session_not_running" if answer == 409 else "x", "message": "No."}})


@pytest.fixture
def rig(recorder_module):
    """A recorder wired to a stand-in server, desktop and clock."""
    server, desktop, clock = Server(), Desktop(), Clock()
    client = httpx.Client(transport=httpx.MockTransport(server))
    recorder = recorder_module.Recorder(
        SERVER, KEY, client=client, account=ACCOUNT, observer_factory=desktop.factory(recorder_module),
        clock=lambda: 1_800_000_000.0, monotonic=clock, jitter=lambda: 1.0)

    def work(*apps, seconds=5.0):
        """One cycle for each app that comes to the front."""
        waits = []
        for app in apps:
            desktop.front = app
            waits.append(recorder.step())
            clock.now += seconds
        return waits

    yield type("Rig", (), {"server": server, "desktop": desktop, "clock": clock, "recorder": recorder,
                           "work": staticmethod(work), "module": recorder_module})
    client.close()


def test_nothing_is_looked_at_until_the_person_starts(rig):
    assert rig.work("excel", "powerpoint", "excel") == [5.0, 5.0, 5.0]
    assert rig.desktop.looks == 0 and rig.desktop.observers == 0 and rig.recorder.waiting == 0
    assert [request.method for request in rig.server.requests] == ["GET", "GET", "GET"]
    assert all(request.headers["authorization"] == f"Bearer {KEY}" for request in rig.server.requests)
    assert all(str(request.url).startswith(SERVER + "/api/v1/external/ekko/") for request in rig.server.requests)


def test_it_hands_over_small_batches_while_recording(rig):
    rig.server.record()
    rig.work("excel", "powerpoint", "excel")
    assert rig.desktop.looks == 3 and rig.recorder.waiting == 3 and rig.server.batches == []
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("excel")  # nothing new in front; what is waiting is now due
    (batch,) = rig.server.batches
    assert set(batch) == {"session_id", "batch_id", "account", "activities"}
    assert batch["session_id"] == "ekko-session-0001" and batch["account"] == ACCOUNT
    assert [activity["app"] for activity in batch["activities"]] == ["excel", "powerpoint", "excel"]
    assert all(set(activity) == {"app", "action", "object_type", "duration_seconds", "occurred_at"}
               and activity["action"] == "switch" and activity["object_type"] == "none" for activity in batch["activities"])
    # When each happened: the time now, less how long ago it was noticed.
    assert [round(1_800_000_000.0 - activity["occurred_at"]) for activity in batch["activities"]] == [45, 40, 35]
    assert rig.recorder.waiting == 0


def test_a_full_buffer_is_handed_over_at_once_and_never_grows_past_its_limit(rig):
    rig.server.record(batch_limit=4)
    rig.work(*["excel", "powerpoint"] * 2, seconds=1.0)
    assert [len(batch["activities"]) for batch in rig.server.batches] == [4] and rig.recorder.waiting == 0
    # With the server unreachable, what waits is capped and the oldest is dropped.
    rig.server.handover = httpx.ConnectError("refused")
    rig.work(*["excel", "powerpoint"] * 300, seconds=0.01)
    assert rig.recorder.waiting <= rig.module.BUFFER_LIMIT + 4


def test_an_app_the_person_did_not_allow_never_leaves_the_computer(rig):
    rig.server.record()
    rig.work("excel", "word", "finder", "secret-tool", None, "powerpoint")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("powerpoint")
    sent = b"".join(request.content for request in rig.server.requests)
    assert [activity["app"] for batch in rig.server.batches for activity in batch["activities"]] == ["excel", "powerpoint"]
    for name in (b"word", b"finder", b"secret-tool"):
        assert name not in sent


def test_pause_stop_and_withdrawal_are_obeyed_at_the_next_read(rig, caplog):
    caplog.set_level(logging.INFO)
    rig.server.record()
    rig.work("excel", "powerpoint")
    assert rig.recorder.waiting == 2 and rig.desktop.looks == 2

    rig.server.wait("session_paused")
    rig.work("excel", "powerpoint", "excel")
    assert rig.desktop.looks == 2            # not one more look
    assert rig.recorder.waiting == 0         # what was waiting is dropped, not kept for later
    assert rig.server.batches == []
    assert "Not recording: recording is paused." in caplog.text

    rig.server.record()                      # resumed
    rig.work("powerpoint")
    assert rig.desktop.observers == 2        # a fresh observer: nothing from before the pause carries over
    assert rig.recorder.waiting == 1

    rig.server.wait("session_stopped")
    rig.work("excel")
    assert rig.recorder.waiting == 0 and rig.desktop.looks == 3

    rig.server.record(session="ekko-session-0002")   # a new session
    rig.work("excel")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("excel")
    assert [batch["session_id"] for batch in rig.server.batches] == ["ekko-session-0002"]

    # Consent withdrawn: the server no longer knows the key.
    rig.server.instructions = httpx.Response(401, json={"detail": {"code": "invalid_device_key", "message": "No."}})
    rig.work("powerpoint")
    assert rig.recorder.exit_code == rig.module.EXIT_KEY_ENDED and rig.recorder.waiting == 0
    assert rig.desktop.looks == 5
    assert "no longer accepts this device key" in caplog.text


def test_a_session_change_between_reads_drops_what_was_waiting(rig):
    rig.server.record(session="ekko-session-0001")
    rig.work("excel", "powerpoint")
    rig.server.record(session="ekko-session-0002")
    rig.work("excel")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("excel")
    (batch,) = rig.server.batches
    assert batch["session_id"] == "ekko-session-0002" and [a["app"] for a in batch["activities"]] == ["excel"]


def test_the_server_s_refusal_of_a_hand_over_is_obeyed(rig):
    rig.server.record()
    rig.server.handover = 409    # the session stopped between the read and the hand-over
    rig.work("excel")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("powerpoint")
    assert len(rig.server.batches) == 1 and rig.recorder.waiting == 0
    rig.server.handover = 422    # a batch the server will never take is not sent again
    rig.work("excel")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("excel", "excel")
    assert len(rig.server.batches) == 2 and rig.recorder.waiting == 0
    rig.server.handover = httpx.Response(403, json={"detail": {"code": "different_account", "message": "No."}})
    rig.work("powerpoint")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("powerpoint")
    assert rig.recorder.exit_code == rig.module.EXIT_OTHER_ACCOUNT and rig.recorder.waiting == 0


def test_it_backs_off_and_looks_at_nothing_while_the_server_cannot_be_reached(rig):
    rig.server.record()
    rig.work("excel")
    for failure in (httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.Response(503), httpx.Response(500),
                    httpx.Response(200, content=b"not json"), httpx.Response(200, json={"record": "yes"})):
        rig.server.instructions = failure
        rig.recorder._unanswered = 0
        waits = rig.work(*["powerpoint"] * 9)
        assert waits == [10.0, 20.0, 40.0, 80.0, 160.0, 300.0, 300.0, 300.0, 300.0], failure
        assert rig.desktop.looks == 1 and rig.recorder.waiting == 0, failure
    rig.server.record()
    assert rig.work("powerpoint") == [5.0] and rig.desktop.looks == 2


def test_a_hand_over_that_fails_is_tried_again_with_the_same_id_then_given_up(rig):
    rig.server.record()
    rig.work("excel")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.server.handover = httpx.Response(503)
    rig.work("powerpoint")
    rig.server.handover = httpx.Response(429, headers={"Retry-After": "120"})
    rig.clock.now += 20
    rig.work("powerpoint")
    assert len(rig.server.batches) == 2
    rig.work("excel", "powerpoint", seconds=30.0)   # inside the wait the server asked for: not tried
    assert len(rig.server.batches) == 2
    rig.server.handover = 200
    rig.clock.now += 120
    rig.work("excel")
    first, second, third = rig.server.batches[:3]
    assert first["batch_id"] == second["batch_id"] == third["batch_id"]
    assert [a["app"] for a in first["activities"]] == [a["app"] for a in third["activities"]] == ["excel", "powerpoint"]
    assert third["activities"][0]["occurred_at"] < first["activities"][0]["occurred_at"]  # as long ago as it now is

    # A batch that still cannot be delivered after five minutes is dropped.
    rig.server.handover = httpx.ConnectError("refused")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("excel")
    held = rig.recorder.waiting
    assert held > 0
    rig.clock.now += rig.module.MAX_HELD_SECONDS + 1
    rig.work("excel")
    assert rig.recorder.waiting < held


def test_the_key_and_what_was_noticed_are_never_logged(rig, caplog):
    caplog.set_level(logging.DEBUG)
    rig.server.record()
    rig.work("excel", "powerpoint")
    rig.clock.now += rig.module.FLUSH_SECONDS
    rig.work("excel")
    for failure in (httpx.ConnectError(f"cannot reach {SERVER} with {KEY}"), httpx.Response(503), httpx.Response(401)):
        rig.server.instructions = failure
        rig.work("powerpoint")
    assert "Handed over 3 activities." in caplog.text
    for secret in (KEY, KEY[21:], "excel", "powerpoint", ACCOUNT):
        assert secret not in caplog.text
    # Each state is said once, not on every read.
    assert caplog.text.count("Recording is on.") == 1


def test_nothing_is_written_to_disk(rig, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    opened = []
    real_open, real_os_open = builtins.open, os.open

    def watch_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in "wax+"):
            opened.append((str(file), mode))
        return real_open(file, mode, *args, **kwargs)

    def watch_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
            opened.append((str(path), flags))
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", watch_open)
    monkeypatch.setattr(os, "open", watch_os_open)
    rig.server.record()
    rig.work(*["excel", "powerpoint"] * 30, seconds=2.0)
    rig.server.handover = httpx.ConnectError("refused")
    rig.work(*["excel", "powerpoint"] * 30, seconds=2.0)
    rig.server.wait()
    rig.work("excel")
    stopped = []
    assert rig.module.run(rig.recorder, stop=lambda: stopped.append(1) or len(stopped) > 3, sleep=lambda _s: None) == 0
    assert len(rig.server.batches) > 2
    assert opened == []
    assert list(tmp_path.iterdir()) == []
    assert not any(isinstance(handler, logging.FileHandler) for handler in logging.getLogger("second_shift_recorder").handlers)


def test_stopping_hands_over_what_is_waiting_once_and_exits_cleanly(rig):
    rig.server.record()
    rig.work("excel", "powerpoint")
    assert rig.server.batches == []
    assert rig.module.run(rig.recorder, stop=lambda: True, sleep=lambda _s: None) == rig.module.EXIT_STOPPED
    (batch,) = rig.server.batches
    assert [a["app"] for a in batch["activities"]] == ["excel", "powerpoint"] and rig.recorder.waiting == 0
    # If that last hand-over cannot be delivered, it is not kept anywhere.
    rig.work("excel")
    rig.server.handover = httpx.ConnectError("refused")
    assert rig.module.run(rig.recorder, stop=lambda: True, sleep=lambda _s: None) == rig.module.EXIT_STOPPED
    assert rig.recorder.waiting == 0


def test_check_asks_once_and_observes_nothing(rig):
    assert rig.recorder.check() == "The key is accepted. Not recording: recording has not been started on the Ekko page."
    rig.server.record()
    assert rig.recorder.check() == "The key is accepted. Recording is on."
    rig.server.instructions = httpx.Response(401)
    assert "no longer accepts this device key" in rig.recorder.check()
    assert rig.recorder.exit_code == rig.module.EXIT_KEY_ENDED
    assert rig.desktop.looks == 0 and rig.server.batches == []


# --- the loop, against the real app ---------------------------------------------------------

@pytest.fixture
def installed(tmp_path, monkeypatch, request):
    """The real app in this process, with Ekko on; yields the person's own client."""
    from maverick import config, world_model
    from maverick.audit import signing
    from maverick_dashboard import ekko_handover_api as handover

    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"ekko-recorder-test:{request.node.nodeid}".encode()
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    signing._reset_injected_keypair_cache()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_EKKO", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_TENANT", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text(
        '[ekko]\nenable = true\nallowed_apps = ["excel", "powerpoint", "word"]\npoll_interval_seconds = 2\n', encoding="utf-8")
    config.reset_config_cache()
    handover._rate_times.clear()
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    signing._reset_injected_keypair_cache()
    config.reset_config_cache()


def test_the_recorder_and_the_server_together(recorder_module, installed):
    person = installed
    assert person.post("/api/v1/ekko/enroll", json={
        "device_id": "desk", "apps": ["excel", "powerpoint"], "days": 14, "acknowledge_capture_scope": True}).status_code == 200
    key = person.post("/api/v1/ekko/device-key", json={"device_id": "desk"}).json()["device_key"]
    desktop, clock = Desktop(), Clock()
    recorder = recorder_module.Recorder(
        "http://127.0.0.1", key, client=TestClient(person.app, base_url="http://127.0.0.1"),
        account=recorder_module.account_fingerprint(), observer_factory=desktop.factory(recorder_module),
        monotonic=clock, jitter=lambda: 1.0)

    def work(*apps):
        for app in apps:
            desktop.front = app
            assert recorder.step() == 2.0  # the server's own poll interval
            clock.now += 2

    def count() -> int:
        return person.get("/api/v1/ekko/status?device_id=desk").json()["event_count"]

    work("excel", "powerpoint")
    assert desktop.looks == 0 and count() == 0  # enrolled, with a key, but the person has not started

    session = person.post("/api/v1/ekko/sessions", json={"device_id": "desk", "acknowledge_capture_scope": True}).json()["session"]["session_id"]
    work("excel", "word", "powerpoint", "secret-tool", "excel")   # word was not chosen at enrollment
    clock.now += recorder_module.FLUSH_SECONDS
    work("excel")
    assert count() == 3
    assert person.get("/api/v1/ekko/device-key?device_id=desk").json()["heard_recently"] is True

    assert person.post(f"/api/v1/ekko/sessions/{session}/pause", json={"device_id": "desk"}).status_code == 200
    looks = desktop.looks
    work("powerpoint", "excel", "powerpoint")
    clock.now += recorder_module.FLUSH_SECONDS
    work("excel")
    assert desktop.looks == looks and count() == 3 and recorder.waiting == 0

    assert person.post(f"/api/v1/ekko/sessions/{session}/resume", json={"device_id": "desk"}).status_code == 200
    work("powerpoint")
    assert recorder_module.run(recorder, stop=lambda: True, sleep=lambda _s: None) == recorder_module.EXIT_STOPPED
    assert count() == 4

    assert person.post("/api/v1/ekko/revoke", json={"device_id": "desk"}).status_code == 200
    looks = desktop.looks
    desktop.front = "excel"
    recorder.exit_code = None
    recorder.step()
    assert recorder.exit_code == recorder_module.EXIT_KEY_ENDED and desktop.looks == looks and count() == 4

    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    events = WorkDiscoveryStore(local_os_principal(), "desk").list_events()
    assert [event.app for event in events] == ["excel", "powerpoint", "excel", "powerpoint"]
    assert {(event.action, event.object_type) for event in events} == {("switch", "none")}


def test_the_recorder_file_is_private_by_default_when_created_as_the_readme_says(recorder_module, tmp_path):
    # The README's way of making the file: create it empty with owner-only access, then fill it.
    path = tmp_path / ".second-shift-recorder.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"server": SERVER, "device_key": KEY}, handle)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert recorder_module.read_settings(path) == (SERVER, KEY)
