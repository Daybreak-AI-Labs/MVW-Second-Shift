"""Second Shift recorder: notices which allowed work apps are in front, on your own computer.

You run this on the Windows or Mac computer you enrolled on the Ekko page of
your Second Shift server. Every few seconds it asks the server whether to
record. Only while your session there is running, it notices when you switch
to one of the apps you allowed and hands that over in small batches.

What it reads from your computer: the program file name (Windows) or bundle
identifier (Mac) of the app in front, and only to look it up in the short
fixed lists below. An app that is not in a list is never named anywhere.

What it never does: read a window title, the screen, the keyboard, the
clipboard, a web address, a file name or anything inside a file; start a
session (only you do, on the page); keep anything on disk (activities wait in
memory, a few hundred at most, and are dropped when recording is not running);
write the key, an app name or an activity to its log.

It needs Python 3.11 or later and ``httpx``; on a Mac also
``pyobjc-framework-Cocoa``. It imports nothing else from Second Shift: the
lists and the two small operating-system readers are copies of the server's
own (``maverick/ekko_daemon.py``, ``maverick/ekko_foreground.py``,
``maverick/work_discovery_identity.py``), kept the same by a test.

Settings: a file only you can read (see the README), by default
``.second-shift-recorder.json`` in your home folder::

    {"server": "https://second-shift.example.com", "device_key": "ekr_..."}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import ntpath
import os
import random
import re
import secrets
import signal
import stat
import sys
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import httpx

VERSION = "1"
DEFAULT_SETTINGS_FILE = "~/.second-shift-recorder.json"
INSTRUCTIONS_PATH = "/api/v1/external/ekko/instructions"
HANDOVER_PATH = "/api/v1/external/ekko/handover"
#: Activities waiting in memory; the oldest is dropped past this.
BUFFER_LIMIT = 200
#: Activities in one hand-over (the server may say fewer).
BATCH_LIMIT = 50
#: An activity waits at most this long before it is handed over.
FLUSH_SECONDS = 30.0
#: A hand-over that still has not been accepted after this long is dropped.
MAX_HELD_SECONDS = 300.0
#: The longest wait between tries when the server cannot be reached.
MAX_BACKOFF_SECONDS = 300.0
REQUEST_TIMEOUT_SECONDS = 10.0

EXIT_STOPPED, EXIT_SETTINGS, EXIT_KEY_ENDED, EXIT_OTHER_ACCOUNT = 0, 2, 3, 4

# Copies of the server's fixed lists. A program that is not here is dropped
# and never named.
WINDOWS_EXECUTABLE_APPS = {
    "chrome.exe": "chrome",
    "msedge.exe": "edge",
    "firefox.exe": "firefox",
    "excel.exe": "excel",
    "powerpnt.exe": "powerpoint",
    "winword.exe": "word",
    "explorer.exe": "file_explorer",
    "pbidesktop.exe": "power_bi",
    "tableau.exe": "tableau",
}
MACOS_BUNDLE_APPS = {
    "com.google.chrome": "chrome", "com.microsoft.edgemac": "edge",
    "org.mozilla.firefox": "firefox", "com.apple.safari": "safari",
    "com.microsoft.excel": "excel", "com.microsoft.powerpoint": "powerpoint",
    "com.microsoft.word": "word", "com.apple.finder": "finder",
}
KNOWN_APPS = frozenset({*WINDOWS_EXECUTABLE_APPS.values(), *MACOS_BUNDLE_APPS.values()})

log = logging.getLogger("second_shift_recorder")


class RecorderError(Exception):
    """A plain message for the person running the recorder. Never holds the key."""


# --- the settings file -------------------------------------------------------------

def acl_is_private(sddl: str, owner_sid: str, user_sid: str) -> bool:
    """Whether a Windows access list lets only this user read the file.

    The system itself and local administrators may also be listed: they can
    read any file on the computer whatever its list says. A list with no
    entries, an entry of an unknown kind or an entry for anyone else fails.
    """
    system_and_admins = {"SY", "BA", "S-1-5-18", "S-1-5-32-544"}
    if owner_sid not in {user_sid, "S-1-5-18", "S-1-5-32-544"} or not sddl.startswith("D:"):
        return False
    entries = re.findall(r"\(([^()]*)\)", sddl)
    if not entries or "NO_ACCESS_CONTROL" in sddl:
        return False
    for entry in entries:
        fields = entry.split(";")
        if len(fields) != 6:
            return False
        if fields[0] == "D":
            continue  # a deny entry only takes access away
        if fields[0] != "A" or fields[5] not in system_and_admins | {user_sid, "OW", "S-1-3-4"}:
            return False
    return True


def _windows_file_acl(path: Path) -> tuple[str, str]:
    """``(access list, owner)`` of a Windows file, as text."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = advapi32.GetNamedSecurityInfoW
    get_info.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD] + [ctypes.POINTER(ctypes.c_void_p)] * 5
    get_info.restype = wintypes.DWORD
    to_sddl = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    to_sddl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                        ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(wintypes.DWORD)]
    to_sddl.restype = wintypes.BOOL
    sid_to_text = advapi32.ConvertSidToStringSidW
    sid_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    sid_to_text.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    # SE_FILE_OBJECT; OWNER + DACL
    result = get_info(str(path), 1, 0x1 | 0x4, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
    if result:
        raise OSError(result, "GetNamedSecurityInfoW failed")
    sddl_text, owner_text = ctypes.c_wchar_p(), ctypes.c_wchar_p()
    try:
        if not to_sddl(descriptor, 1, 0x4, ctypes.byref(sddl_text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not sid_to_text(owner, ctypes.byref(owner_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        return str(sddl_text.value or ""), str(owner_text.value or "")
    finally:
        for held in (sddl_text, owner_text, descriptor):
            if held:
                kernel32.LocalFree(held)


def _windows_user_sid() -> str:
    """The security identifier of the account this program runs as."""
    import ctypes
    from ctypes import wintypes

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("User", SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    token_info = advapi32.GetTokenInformation
    token_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    token_info.restype = wintypes.BOOL
    sid_to_text = advapi32.ConvertSidToStringSidW
    sid_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    sid_to_text.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    token = wintypes.HANDLE()
    if not open_token(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        token_info(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
        if not needed.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not token_info(token, 1, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_text = ctypes.c_wchar_p()
        try:
            if not sid_to_text(ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents.User.Sid, ctypes.byref(sid_text)):
                raise ctypes.WinError(ctypes.get_last_error())
            return str(sid_text.value or "")
        finally:
            if sid_text:
                kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def _read_private(path: Path) -> str:
    """Read the settings file, refusing one that another user could read."""
    refusal = (f"The settings file {path} can be read by other users of this computer, so the recorder will not "
               "use it. Make it readable by you only (the README shows how), then start again.")
    if os.name == "nt":
        try:
            if path.is_symlink() or not path.is_file():
                raise RecorderError(f"The settings file {path} was not found.")
            private = acl_is_private(*_windows_file_acl(path), _windows_user_sid())
        except OSError as exc:
            raise RecorderError(f"The settings file {path} could not be checked.") from exc
        if not private:
            raise RecorderError(refusal)
        return path.read_text(encoding="utf-8")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise RecorderError(f"The settings file {path} was not found, or is a link.") from exc
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RecorderError(refusal)
        return handle.read(65_536)


def read_settings(path: Path) -> tuple[str, str]:
    """``(server address, device key)`` from a file only this user can read."""
    try:
        value = json.loads(_read_private(path))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RecorderError(f"The settings file {path} is not in the expected form. See the README.") from exc
    if not isinstance(value, dict) or set(value) != {"server", "device_key"}:
        raise RecorderError(f"The settings file {path} must hold exactly \"server\" and \"device_key\".")
    server, key = value["server"], value["device_key"]
    if not isinstance(key, str) or not key or key != key.strip() or any(ord(char) < 33 for char in key):
        raise RecorderError(f"The device key in {path} is missing or has spaces in it. Copy it again from the Ekko page.")
    try:
        address = urlsplit(server) if isinstance(server, str) else None
        host = address.hostname if address is not None else None
    except ValueError:
        address = host = None
    # Over plain http the key would cross the network readable by anyone, so
    # http is accepted only for a server on this same computer.
    if (address is None or not host or address.username or address.query or address.fragment
            or address.scheme not in ("https", "http")
            or (address.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"})):
        raise RecorderError(f"The server address in {path} must start with https://.")
    return server.rstrip("/"), key


# --- noticing the app in front -----------------------------------------------------

def _windows_foreground_executable() -> str | None:
    """Only the file name of the program in front. No window title is read."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_foreground = user32.GetForegroundWindow
    get_foreground.argtypes = []
    get_foreground.restype = wintypes.HWND
    get_pid = user32.GetWindowThreadProcessId
    get_pid.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    get_pid.restype = wintypes.DWORD
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    query_image.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    hwnd = get_foreground()
    if not hwnd:
        return None
    pid = wintypes.DWORD()
    if not get_pid(hwnd, ctypes.byref(pid)) or not pid.value:
        return None
    handle = open_process(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32_768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not query_image(handle, 0, buffer, ctypes.byref(size)):
            return None
        return ntpath.basename(buffer.value).casefold()  # the folder path is discarded here
    finally:
        close_handle(handle)


def _windows_foreground_app() -> str | None:
    return WINDOWS_EXECUTABLE_APPS.get(ntpath.basename(str(_windows_foreground_executable() or "")).casefold())


def _macos_foreground_app() -> str | None:
    """Only the bundle identifier of the app in front, looked up in the list."""
    import objc
    from AppKit import NSWorkspace
    from Foundation import NSDate, NSRunLoop

    with objc.autorelease_pool():
        # macOS refreshes "the app in front" for a program only while that
        # program services its run loop; give it a moment before each look.
        NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.01))
        app = NSWorkspace.sharedWorkspace().frontmostApplication()
        identifier = app.bundleIdentifier() if app is not None else None
        return MACOS_BUNDLE_APPS.get(str(identifier or "").casefold())


class ForegroundObserver:
    """Turns "which listed app is in front" into switches, without content.

    ``observe`` answers only when the app in front changed to a listed app:
    its name and how long the previous one was in front. An app that is not
    listed is remembered only as "something else", so coming back to a listed
    app counts as a new switch.
    """

    def __init__(self, resolver: Callable[[], str | None], clock: Callable[[], float] = time.monotonic):
        self._resolver, self._clock = resolver, clock
        self._last_marker: str | None = None
        self._last_switch: float | None = None

    def observe(self) -> tuple[str, float] | None:
        app = self._resolver()
        if app not in KNOWN_APPS:
            app = None
        marker = app or "__unobserved__"
        if marker == self._last_marker:
            return None
        now = float(self._clock())
        duration = max(0.0, min(86_400.0, now - self._last_switch)) if self._last_switch is not None else 0.0
        self._last_marker, self._last_switch = marker, now
        return (app, duration) if app else None


def platform_observer() -> ForegroundObserver:
    """The observer for this computer, or a plain reason there is none."""
    if sys.platform == "win32":
        return ForegroundObserver(_windows_foreground_app)
    if sys.platform == "darwin":
        try:
            import AppKit  # noqa: F401
            import Foundation  # noqa: F401
            import objc  # noqa: F401
        except ImportError as exc:
            raise RecorderError("On a Mac the recorder needs pyobjc-framework-Cocoa. Install it, then start again.") from exc
        return ForegroundObserver(_macos_foreground_app)
    raise RecorderError("This recorder runs on Windows and macOS.")


def _os_account() -> str:
    """The operating-system account this program runs as (the server's own rule)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        get_name = ctypes.WinDLL("secur32", use_last_error=True).GetUserNameExW
        get_name.argtypes = [ctypes.c_int, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        get_name.restype = wintypes.BOOL
        size = wintypes.DWORD(512)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not get_name(2, buffer, ctypes.byref(size)) or not buffer.value.strip():  # NameSamCompatible
            raise RecorderError("The recorder could not tell which Windows account it runs as.")
        return "os:windows:" + buffer.value.strip().casefold()
    return f"os:posix:{os.geteuid()}"


def account_fingerprint() -> str:
    """A one-way fingerprint of the account. The account name is never sent."""
    return hashlib.sha256(("second-shift-recorder-account:v1:" + _os_account()).encode("utf-8")).hexdigest()


# --- the loop ----------------------------------------------------------------------

class _Finished(Exception):
    """The key is no use any more; the recorder stops with this exit code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


_WAITING = {
    "ekko_off": "Ekko is turned off on the server",
    "enrollment_not_current": "this computer needs to be enrolled again on the Ekko page",
    "emergency_stop": "everything is stopped on the server",
    "session_paused": "recording is paused",
    "session_stopped": "recording is stopped",
    "session_none": "recording has not been started on the Ekko page",
}


class Recorder:
    """Ask, observe when told to, hand over; and forget when told to wait.

    The app in front is only looked at straight after the server has said, in
    that same cycle, that recording is running. Any other answer, or no
    answer, drops the observer, the waiting activities and any batch not yet
    accepted.
    """

    def __init__(
        self, server: str, device_key: str, *, client: httpx.Client, account: str,
        observer_factory: Callable[[], ForegroundObserver] = platform_observer,
        clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = lambda: random.uniform(0.8, 1.2),
    ):
        self._server, self._client, self._account = server, client, account
        self._headers = {"Authorization": "Bearer " + device_key, "User-Agent": "second-shift-recorder/" + VERSION}
        self._observer_factory, self._clock, self._monotonic, self._jitter = observer_factory, clock, monotonic, jitter
        self._observer: ForegroundObserver | None = None
        self._buffer: deque[tuple[str, float, float]] = deque(maxlen=BUFFER_LIMIT)  # app, seconds, when (monotonic)
        self._pending: tuple[str, list[tuple[str, float, float]], float] | None = None  # batch id, activities, since
        self._session: str | None = None
        self._batch_limit = BATCH_LIMIT
        self._poll = 5.0
        self._unanswered = 0  # instruction reads in a row with no usable answer
        self._refusals = 0  # hand-over tries in a row the server could not take
        self._retry_at = 0.0
        self._said: str | None = None
        self.exit_code: int | None = None

    @property
    def waiting(self) -> int:
        """How many activities are held in memory right now."""
        return len(self._buffer) + (len(self._pending[1]) if self._pending else 0)

    def _say(self, text: str) -> None:
        if text != self._said:  # once per change, not once per poll
            self._said = text
            log.info(text)

    def _forget(self) -> None:
        self._observer = None
        self._buffer.clear()
        self._pending = None

    def _request(self, method: str, path: str, body: dict | None = None) -> httpx.Response | None:
        """One call. ``None`` means the server could not be reached; the reason
        is logged by kind only, because an error text may quote the request."""
        try:
            return self._client.request(method, self._server + path, headers=self._headers, json=body)
        except httpx.HTTPError as exc:
            log.warning("The server could not be reached (%s).", type(exc).__name__)
            return None

    def _refused(self, response: httpx.Response) -> None:
        """End the recorder when the server's refusal means the key is no use."""
        try:
            detail = response.json().get("detail")
            code = detail.get("code", "") if isinstance(detail, dict) else ""
        except (ValueError, AttributeError):
            code = ""
        if response.status_code == 401:
            raise _Finished(EXIT_KEY_ENDED, "The server no longer accepts this device key: consent was withdrawn or "
                                            "ended, or the key was replaced. Create a new key on the Ekko page.")
        if response.status_code == 403 and code == "different_account":
            raise _Finished(EXIT_OTHER_ACCOUNT, "This device key was first used from a different computer account. "
                                                "Create a new key on the Ekko page for this computer.")

    def _back_off(self, tries: int, response: httpx.Response | None = None) -> float:
        """How long to wait after ``tries`` failures in a row: longer each time."""
        delay = min(MAX_BACKOFF_SECONDS, self._poll * 2 ** min(tries, 10)) * self._jitter()
        try:
            asked = float(response.headers.get("retry-after", 0)) if response is not None else 0.0
        except ValueError:
            asked = 0.0
        return min(MAX_BACKOFF_SECONDS, max(delay, asked))

    def _instructions(self) -> dict | None:
        """The server's current instructions, or ``None`` when there are none to trust."""
        response = self._request("GET", INSTRUCTIONS_PATH)
        if response is None:
            return None
        if response.status_code != 200:
            self._refused(response)
            log.warning("The server did not give instructions (status %s).", response.status_code)
            return None
        try:
            value = response.json()
            record = value["record"] is True
            session = value["session"]["id"] if record else None
            poll = float(value["poll_interval_seconds"])
            allowed = frozenset(app for app in value["allowed_apps"] if isinstance(app, str))
            limit = int(value.get("batch_limit", BATCH_LIMIT))
        except (ValueError, TypeError, KeyError):
            log.warning("The server's instructions were not understood.")
            return None
        if record and not isinstance(session, str):
            return None
        self._poll = max(1.0, min(300.0, poll))
        self._batch_limit = max(1, min(BATCH_LIMIT, limit))
        return {"session": session, "allowed": allowed, "reason": str(value.get("reason", ""))}

    def _observe(self, allowed: frozenset[str]) -> None:
        try:
            if self._observer is None:
                self._observer = self._observer_factory()
            seen = self._observer.observe()
        except Exception as exc:
            log.warning("The app in front could not be read (%s).", type(exc).__name__)
            self._observer = None
            return
        if seen is not None and seen[0] in allowed:
            self._buffer.append((seen[0], float(seen[1]), self._monotonic()))

    def _due(self, final: bool) -> bool:
        if not self._buffer:
            return False
        return final or len(self._buffer) >= self._batch_limit or self._monotonic() - self._buffer[0][2] >= FLUSH_SECONDS

    def _hand_over(self, final: bool = False) -> None:
        """Hand over what is due, in one small batch."""
        if self._pending is None and self._due(final):
            count = min(self._batch_limit, len(self._buffer))
            self._pending = ("b-" + secrets.token_hex(12), [self._buffer.popleft() for _ in range(count)], self._monotonic())
        if self._pending is None or (self._monotonic() < self._retry_at and not final):
            return
        batch_id, activities, since = self._pending
        if self._monotonic() - since > MAX_HELD_SECONDS:
            self._pending = None  # too old to be believed; the server would move its times anyway
            return
        now, mono = self._clock(), self._monotonic()
        response = self._request("POST", HANDOVER_PATH, {
            "session_id": self._session, "batch_id": batch_id, "account": self._account,
            "activities": [{"app": app, "action": "switch", "object_type": "none", "duration_seconds": seconds,
                            "occurred_at": now - (mono - seen)} for app, seconds, seen in activities],
        })
        if response is None or response.status_code == 429 or response.status_code >= 500:
            # Kept, and tried again later with the same id so it is never stored twice.
            self._refusals += 1
            self._retry_at = self._monotonic() + self._back_off(self._refusals, response)
            return
        self._pending, self._refusals, self._retry_at = None, 0, 0.0
        if response.status_code == 200:
            log.info("Handed over %d activities.", len(activities))
            return
        self._refused(response)
        if response.status_code == 409:
            self._forget()  # the server is not recording: nothing waiting may be kept
        log.warning("The server did not accept a hand-over (status %s).", response.status_code)

    def step(self) -> float:
        """One cycle. Returns how many seconds to wait before the next."""
        try:
            told = self._instructions()
            if told is None:
                self._forget()
                self._unanswered += 1
                self._say("Not recording: the server's instructions could not be read.")
                return self._back_off(self._unanswered)
            self._unanswered = 0
            if told["session"] is None:
                self._forget()
                self._say("Not recording: " + _WAITING.get(told["reason"], "the server says to wait") + ".")
                return self._poll
            if told["session"] != self._session:
                self._forget()  # nothing noticed under one session is handed to another
                self._session = told["session"]
            self._say("Recording is on.")
            self._observe(told["allowed"])
            self._hand_over()
            return self._poll
        except _Finished as finished:
            self._forget()
            self.exit_code = finished.code
            log.error("%s", finished)
            return 0.0

    def check(self) -> str:
        """Ask the server once, observing nothing, and say what it answered."""
        try:
            told = self._instructions()
        except _Finished as finished:
            self.exit_code = finished.code
            return str(finished)
        if told is None:
            self.exit_code = EXIT_SETTINGS
            return "The server's instructions could not be read. Check the server address and try again."
        if told["session"] is None:
            return "The key is accepted. Not recording: " + _WAITING.get(told["reason"], "the server says to wait") + "."
        return "The key is accepted. Recording is on."

    def finish(self) -> None:
        """Hand over what is still waiting, once, then forget everything."""
        try:
            if self._session is not None and self.exit_code is None:
                self._hand_over(final=True)
        except _Finished:
            pass
        self._forget()


def run(recorder: Recorder, *, stop: Callable[[], bool], sleep: Callable[[float], None] = time.sleep) -> int:
    """Run until asked to stop or until the key is no use. Returns the exit code."""
    while not stop() and recorder.exit_code is None:
        until = time.monotonic() + recorder.step()
        while not stop() and recorder.exit_code is None and time.monotonic() < until:
            sleep(min(0.5, max(0.0, until - time.monotonic())))
    recorder.finish()
    return recorder.exit_code if recorder.exit_code is not None else EXIT_STOPPED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Second Shift recorder: notices which allowed work apps are in front.")
    parser.add_argument("--config", default=DEFAULT_SETTINGS_FILE, help="the settings file (default: %(default)s)")
    parser.add_argument("--check", action="store_true", help="check the settings file and the key, record nothing, then stop")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # its request lines are not needed
    try:
        server, key = read_settings(Path(args.config).expanduser())
        if not args.check:
            platform_observer()  # say now, in plain words, if this computer cannot be observed
        account = account_fingerprint()
    except RecorderError as exc:
        log.error("%s", exc)
        return EXIT_SETTINGS
    stopping: list[int] = []
    for name in ("SIGINT", "SIGTERM"):
        signal.signal(getattr(signal, name), lambda number, _frame: stopping.append(number))
    with httpx.Client(follow_redirects=False, timeout=REQUEST_TIMEOUT_SECONDS) as client:
        recorder = Recorder(server, key, client=client, account=account)
        if args.check:
            log.info("%s", recorder.check())
            return recorder.exit_code if recorder.exit_code is not None else EXIT_STOPPED
        log.info("Recorder started for %s. Press Ctrl+C to stop.", urlsplit(server).hostname)
        code = run(recorder, stop=lambda: bool(stopping))
    log.info("Recorder stopped.")
    return code


if __name__ == "__main__":
    sys.exit(main())
