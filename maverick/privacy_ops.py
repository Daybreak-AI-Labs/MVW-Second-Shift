"""Privacy operations record types: the privacy operations data plane.

Four privacy record types over one tenant-scoped JSON store, each pairing a
deterministic, explainable engine with a lifecycle the Privacy workspace can
review — the same design as :mod:`maverick.assessment` (records are governance
artifacts meant to be exported and audited, not secrets):

* **DPA reviews** — a Data Processing Agreement checked clause-by-clause
  against the GDPR Art. 28(3) requirements (documented instructions,
  confidentiality, Art. 32 security, sub-processor authorization, data-subject
  assistance, breach notification, deletion/return, audit rights) plus
  transfer-safeguard and retention checks. Detection is keyword-heuristic and
  honest: ``present`` / ``unclear`` / ``missing`` with the matched excerpt, so
  a reviewer can verify every call. Residual risk falls as required clauses
  are found; inherent risk reflects the exposure the document itself declares
  (transfers, special categories, broad scopes).
* **AI systems registry** — an inventory of AI systems classified against the
  EU AI Act's tiers (prohibited / high / limited / minimal) using the Act's
  own category tests (Annex III high-risk areas, Art. 5 prohibited practices,
  Art. 50 transparency triggers), each classification carrying its matched
  signals and the tier's obligations. Screening aid, not legal advice.
* **RoPA / data inventory** — Art. 30(1) records of processing activities.
  ``draft_from_assessment`` turns a completed PIA into a draft RoPA entry
  (answers map onto Art. 30 fields), which is the system-of-record moment:
  assessments feed the inventory instead of dying in a filing cabinet.
* **DSAR requests** — a tracker with statutory due dates (30 days) over the
  REAL fulfillment machinery: access/portability exports run
  :func:`maverick.dsar.export_subject_data`; erasure records a structured
  argument vector for an authenticated operator workflow (destructive
  fulfillment stays deliberate and no shell command is rendered).

Gated by ``[privacy_ops] enable`` (default on — local record stores, already
behind the workspace's operate floor). Everything fails soft and nothing here
auto-approves, auto-erases, or bypasses the human gates.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from pathlib import Path

_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_PRIVACY_JSON_BYTES = 16 * 1024 * 1024
_MAX_PRIVACY_ENVELOPE_BYTES = 128
_MAX_DOCUMENT_INPUT_BYTES = 16 * 1024 * 1024
_MAX_PDF_STREAMS = 256
_MAX_AUDIT_PENDING_RECEIPTS = 128
_RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def _unsafe_path_alias(path: Path, info: os.stat_result) -> bool:
    """POSIX symlink or Windows junction/reparse point."""
    is_junction = getattr(path, "is_junction", None)
    return (
        stat.S_ISLNK(info.st_mode)
        or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)
        or bool(callable(is_junction) and is_junction())
    )


def _component_identity(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        getattr(info, "st_file_attributes", None),
        getattr(info, "st_reparse_tag", None),
    )


def _file_identity(info: os.stat_result) -> tuple:
    """Fields stable across path-stat and descriptor-stat on Windows/POSIX."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", None),
    )


def _validated_private_directory(
    directory: Path,
    *,
    must_exist: bool,
) -> tuple[Path, tuple[tuple, ...]]:
    """Validate every lexical component without following path aliases."""
    from .file_lock import private_path_is_restricted

    absolute = Path(os.path.abspath(os.fspath(directory)))
    parts = absolute.parts
    cursor = Path(parts[0])
    identities: list[tuple] = []
    found_final = False
    for index, part in enumerate(parts):
        if index:
            cursor /= part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise PermissionError(
                f"privacy store path could not be verified: {cursor}"
            ) from exc
        if _unsafe_path_alias(cursor, info):
            raise PermissionError(
                f"privacy store path aliases are not permitted: {cursor}"
            )
        if not stat.S_ISDIR(info.st_mode):
            raise PermissionError(
                f"privacy store component is not a directory: {cursor}"
            )
        identities.append(_component_identity(info))
        found_final = index == len(parts) - 1
    if must_exist and not found_final:
        raise FileNotFoundError(absolute)
    if found_final and not private_path_is_restricted(absolute, 0o700):
        raise PermissionError(
            f"privacy store directory is not private: {absolute}"
        )
    return absolute, tuple(identities)


class _SealedPrivateRecord(dict):
    """Read-local envelope custody; never part of the serialized record body."""

    def __init__(self, value: dict, original: bytes) -> None:
        super().__init__(value)
        self.original_envelope = original


def _decode_private_json(raw: bytes) -> dict:
    from .crypto_at_rest import EncryptionUnavailable, is_sealed, unseal

    sealed = is_sealed(raw)
    try:
        plaintext = unseal(raw) if sealed else raw
    except EncryptionUnavailable as exc:
        raise PrivacyStateError("privacy record encryption did not authenticate") from exc
    if len(plaintext) > _MAX_PRIVACY_JSON_BYTES:
        raise ValueError("privacy state exceeds the decoded size limit")
    value = json.loads(plaintext.decode("utf-8", errors="strict"))
    if not isinstance(value, dict):
        raise ValueError("privacy state is not a JSON object")
    return _SealedPrivateRecord(value, raw) if sealed else value


def _read_private_json(path: Path, *, root: Path) -> dict:
    """No-follow, handle-bound JSON read from a verified private directory."""
    from .file_lock import private_path_is_restricted

    root, components_before = _validated_private_directory(root, must_exist=True)
    lexical = Path(os.path.abspath(os.fspath(path)))
    if lexical.parent != root:
        raise PermissionError("privacy state path escaped its store")
    before = lexical.lstat()
    if (
        _unsafe_path_alias(lexical, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise PermissionError("privacy state is not a single-link regular file")
    if before.st_size > _MAX_PRIVACY_JSON_BYTES + _MAX_PRIVACY_ENVELOPE_BYTES:
        raise ValueError("privacy state exceeds the size limit")
    if not private_path_is_restricted(lexical, 0o600):
        raise PermissionError("privacy state file is not private")

    root_fd: int | None = None
    fd: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            if os.name != "nt":
                root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                root_flags |= getattr(os, "O_NOFOLLOW", 0)
                root_fd = os.open(root, root_flags)
                if _component_identity(os.fstat(root_fd)) != components_before[-1]:
                    raise PermissionError("privacy store root changed during open")
                fd = os.open(lexical.name, flags, dir_fd=root_fd)
            else:
                # Windows CRT descriptors have no openat. The verified component
                # identities are rechecked before returning any bytes; final
                # reparse points are rejected from both path and handle metadata.
                fd = os.open(lexical, flags)
        except OSError as exc:
            # A record that existed at the lstat boundary but cannot be opened
            # through the no-follow handle boundary changed underneath us.
            # POSIX reports a leaf swap to a symlink as ELOOP (a plain
            # OSError), while Windows generally exposes the later identity
            # mismatch as PermissionError. Normalize both hosts to the same
            # fail-closed API instead of misclassifying the race as corrupt
            # JSON in _RecordStore._read_path.
            raise PermissionError("privacy state changed during open") from exc
        opened = os.fstat(fd)
        if (
            _unsafe_path_alias(lexical, opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _file_identity(opened) != _file_identity(before)
        ):
            raise PermissionError("privacy state changed during open")
        chunks: list[bytes] = []
        remaining = _MAX_PRIVACY_JSON_BYTES + _MAX_PRIVACY_ENVELOPE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_PRIVACY_JSON_BYTES + _MAX_PRIVACY_ENVELOPE_BYTES:
            raise ValueError("privacy state exceeds the size limit")
        after = os.fstat(fd)
        current = lexical.lstat()
        _, components_after = _validated_private_directory(
            root,
            must_exist=True,
        )
        if (
            _file_identity(after) != _file_identity(opened)
            or _file_identity(current) != _file_identity(before)
            or components_after != components_before
            or not private_path_is_restricted(lexical, 0o600)
        ):
            raise PermissionError("privacy state changed during read")
    finally:
        if fd is not None:
            os.close(fd)
        if root_fd is not None:
            os.close(root_fd)
    return _decode_private_json(raw)


class RecordConflict(RuntimeError):
    """A caller tried to replace a stale privacy record revision."""


class AuditOutboxError(RuntimeError):
    """A privacy mutation cannot preserve a valid bounded audit outbox."""


class PrivacyStateError(RuntimeError):
    """A present governed privacy record cannot be trusted or recovered."""


def _validated_audit_queue(record: dict) -> list[dict]:
    """Return a shape- and size-validated copy of an embedded outbox."""
    raw = record.get("_audit_pending")
    if raw is None:
        return []
    if isinstance(raw, dict):
        queue = [raw]
    elif isinstance(raw, list):
        queue = list(raw)
    else:
        raise AuditOutboxError("privacy audit outbox has invalid shape")
    if len(queue) > _MAX_AUDIT_PENDING_RECEIPTS:
        raise AuditOutboxError("privacy audit outbox exceeds receipt cap")
    event_ids: set[str] = set()
    for receipt in queue:
        if not isinstance(receipt, dict):
            raise AuditOutboxError("privacy audit outbox receipt is not an object")
        event_id = receipt.get("event_id")
        action = receipt.get("action")
        actor = receipt.get("actor")
        prepared_at = receipt.get("prepared_at")
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 128:
            raise AuditOutboxError("privacy audit receipt has invalid event id")
        if event_id in event_ids:
            raise AuditOutboxError("privacy audit outbox has duplicate event id")
        event_ids.add(event_id)
        if not isinstance(action, str) or not 1 <= len(action) <= 64:
            raise AuditOutboxError("privacy audit receipt has invalid action")
        if not isinstance(actor, str) or not 1 <= len(actor) <= 256:
            raise AuditOutboxError("privacy audit receipt has invalid actor")
        if isinstance(prepared_at, bool):
            raise AuditOutboxError("privacy audit receipt has invalid timestamp")
        try:
            timestamp = float(prepared_at)
        except (TypeError, ValueError) as exc:
            raise AuditOutboxError(
                "privacy audit receipt has invalid timestamp"
            ) from exc
        if not math.isfinite(timestamp) or timestamp <= 0:
            raise AuditOutboxError("privacy audit receipt has invalid timestamp")
        digest = receipt.get("record_sha256")
        if digest is not None and (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise AuditOutboxError("privacy audit receipt has invalid record digest")
        revision = receipt.get("revision")
        if revision is not None and (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
        ):
            raise AuditOutboxError("privacy audit receipt has invalid revision")
        status = receipt.get("status")
        if status is not None and (
            not isinstance(status, str) or len(status) > 64
        ):
            raise AuditOutboxError("privacy audit receipt has invalid status")
    return queue


def _validate_document_evidence_record(record: dict) -> None:
    """Verify bounded provenance metadata before a DPA record is served."""
    evidence = record.get("document_evidence")
    if evidence is None:
        return
    if not isinstance(evidence, dict):
        raise PrivacyStateError("document evidence is invalid")
    if evidence.get("schema") != "second-shift.document-extraction-evidence.v1":
        raise PrivacyStateError("document evidence schema is invalid")
    for key in (
        "source_binding_sha256",
        "document_sha256",
        "extracted_text_sha256",
        "binding_sha256",
    ):
        if not isinstance(evidence.get(key), str) or re.fullmatch(
            r"[0-9a-f]{64}", evidence[key]
        ) is None:
            raise PrivacyStateError("document evidence digest is invalid")
    bounded_strings = {
        "source": 64,
        "resolved_mime": 255,
        "method": 64,
        "scope": 64,
        "confidence": 32,
    }
    for key, limit in bounded_strings.items():
        value = evidence.get(key)
        if not isinstance(value, str) or not 1 <= len(value) <= limit:
            raise PrivacyStateError("document evidence metadata is invalid")
    size = evidence.get("document_size_bytes")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 <= size <= _MAX_DOCUMENT_INPUT_BYTES
    ):
        raise PrivacyStateError("document evidence size is invalid")
    if not isinstance(evidence.get("review_required"), bool):
        raise PrivacyStateError("document evidence review policy is invalid")
    streams = evidence.get("referenced_streams")
    if streams is not None and (
        not isinstance(streams, int)
        or isinstance(streams, bool)
        or not 0 <= streams <= _MAX_PDF_STREAMS
    ):
        raise PrivacyStateError("document evidence stream count is invalid")
    bound = dict(evidence)
    claimed = bound.pop("binding_sha256")
    if _canonical_sha256(bound) != claimed:
        raise PrivacyStateError("document evidence binding does not verify")
    if (
        record.get("extraction_confidence") != evidence["confidence"]
        or record.get("review_required") is not evidence["review_required"]
        or (
            evidence["confidence"] == "untrusted"
            and evidence["review_required"] is not True
        )
    ):
        raise PrivacyStateError("document evidence policy binding is invalid")


class _RecordStore:
    """Tenant-scoped, atomic JSON records with per-record strict locking.

    Every mutation is a locked read-modify-atomic-replace and increments the
    monotonic ``revision``. That prevents torn reads and lost updates across the
    dashboard, workers, and multiple server processes; ``expected_revision``
    adds compare-and-swap for callers that reviewed a specific version.
    """

    def __init__(self, name: str, prefix: str) -> None:
        self.name = name
        self.prefix = prefix

    def _dir(self) -> Path:
        from .paths import data_dir
        return data_dir(self.name)

    def new_id(self) -> str:
        return f"{self.prefix}-{uuid.uuid4().hex[:10]}"

    def _path(self, record_id: str) -> Path | None:
        record_id = str(record_id or "")
        if (
            not _RECORD_ID_RE.fullmatch(record_id)
            or not record_id.startswith(f"{self.prefix}-")
        ):
            return None
        base, _ = _validated_private_directory(
            self._dir(),
            must_exist=False,
        )
        return base / f"{record_id}.json"

    def _read_path(self, path: Path) -> dict | None:
        try:
            value = _read_private_json(path, root=path.parent)
            expected_id = path.stem
            if (
                value.get("id") != expected_id
                or not _RECORD_ID_RE.fullmatch(expected_id)
                or not expected_id.startswith(f"{self.prefix}-")
            ):
                raise PermissionError(
                    "privacy record identity does not match its store path"
                )
            try:
                _validated_audit_queue(value)
            except AuditOutboxError as exc:
                raise PermissionError(
                    "privacy record has an invalid audit outbox"
                ) from exc
            self._revision(value)
            _validate_document_evidence_record(value)
            return value
        except PermissionError:
            raise
        except FileNotFoundError:
            return None
        except PrivacyStateError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise PrivacyStateError(
                "privacy record is unreadable or corrupt") from exc

    @staticmethod
    def _revision(record: dict | None) -> int:
        if record is None or "revision" not in record:
            return 0
        revision = record.get("revision")
        if (
            not isinstance(revision, int)
            or isinstance(revision, bool)
            or revision < 0
        ):
            raise PermissionError("privacy record revision is invalid")
        return revision

    @staticmethod
    def _expected_revision(value: int | None) -> int | None:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("expected privacy record revision is invalid")
        return value

    @classmethod
    def _write_path(
        cls,
        path: Path,
        record: dict,
        previous: dict | None,
        *,
        bump_revision: bool = True,
        effect_guard=None,
    ) -> dict:
        from .file_lock import atomic_write_text

        saved = dict(record)
        prior_revision = cls._revision(previous)
        saved["revision"] = prior_revision + (1 if bump_revision else 0)
        logical_record = {
            key: value for key, value in saved.items()
            if key != "_audit_pending"
        }
        record_sha256 = hashlib.sha256(json.dumps(
            logical_record,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")).hexdigest()
        # Bind each durable outbox receipt to the exact logical version and
        # status committed by the mutation that created it.  A later retry
        # must not accidentally describe the record's newer state.
        pending_items = _validated_audit_queue(saved)
        if pending_items:
            stamped: list[dict] = []
            for item in pending_items:
                receipt = dict(item)
                receipt.setdefault("revision", saved["revision"])
                receipt.setdefault("status", str(saved.get("status") or ""))
                receipt.setdefault("record_sha256", record_sha256)
                stamped.append(receipt)
            saved["_audit_pending"] = stamped
            _validated_audit_queue(saved)
        else:
            saved.pop("_audit_pending", None)
        try:
            rendered = json.dumps(
                saved,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise PrivacyStateError("privacy record is not valid bounded JSON") from exc
        if len(rendered.encode("utf-8")) > _MAX_PRIVACY_JSON_BYTES:
            raise PrivacyStateError("privacy record exceeds the 16 MiB JSON limit")
        if isinstance(previous, _SealedPrivateRecord):
            from .crypto_at_rest import EncryptionUnavailable, reseal
            from .file_lock import atomic_write_bytes

            try:
                sealed = reseal(previous.original_envelope, rendered.encode("utf-8"))
            except EncryptionUnavailable as exc:
                raise PrivacyStateError("privacy record encryption did not authenticate") from exc
            if effect_guard is None:
                atomic_write_bytes(path, sealed, mode=0o600)
            else:
                atomic_write_bytes(path, sealed, mode=0o600, effect_guard=effect_guard)
        else:
            # Existing local JSON policy remains unchanged: this is encrypted
            # record compatibility, not a migration of all legacy plaintext.
            if effect_guard is None:
                atomic_write_text(path, rendered, mode=0o600)
            else:
                atomic_write_text(path, rendered, mode=0o600, effect_guard=effect_guard)
        return saved

    def save(self, record: dict, *, expected_revision: int | None = None, effect_guard=None) -> dict:
        """Atomically create/replace a record, optionally with CAS."""
        from .file_lock import cross_process_lock, ensure_private_directory

        path = self._path(str(record.get("id") or ""))
        if path is None:
            raise ValueError("invalid privacy record id")
        ensure_private_directory(path.parent)
        _validated_private_directory(path.parent, must_exist=True)
        with cross_process_lock(path, strict=True):
            current = self._read_path(path)
            current_revision = self._revision(current)
            expected = self._expected_revision(expected_revision)
            if expected is not None and current_revision != expected:
                raise RecordConflict(
                    f"privacy record changed (expected revision "
                    f"{expected_revision}, found {current_revision})"
                )
            return self._write_path(path, record, current, effect_guard=effect_guard)

    def load(self, record_id: str) -> dict | None:
        from .file_lock import cross_process_lock

        path = self._path(record_id)
        if path is None:
            return None
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if _unsafe_path_alias(path, info):
            raise PermissionError("privacy record path alias is not permitted")
        with cross_process_lock(path, strict=True):
            return self._read_path(path)

    def list(self) -> list[dict]:
        from .file_lock import cross_process_lock

        d, _ = _validated_private_directory(self._dir(), must_exist=False)
        if not d.exists():
            return []
        out = []
        for p in d.glob("*.json"):
            info = p.lstat()
            if _unsafe_path_alias(p, info):
                raise PermissionError("privacy record path alias is not permitted")
            with cross_process_lock(p, strict=True):
                record = self._read_path(p)
            if record is not None:
                out.append(record)
        return sorted(out, key=lambda r: r.get("created_at", 0), reverse=True)

    def list_bounded(self, *, limit: int) -> list[dict]:
        """Read at most ``limit`` records after validating every store path.

        Exact collection-wide ``created_at`` ordering requires deserializing
        every legacy JSON record because the timestamp is stored only inside
        the document.  A bounded read instead ranks the fully validated paths
        by protected-file modification time, reads only that candidate window,
        and preserves the established ``created_at`` order within the window.
        Unbounded :meth:`list` retains its exact historical semantics.
        """
        from .file_lock import cross_process_lock, private_path_is_restricted

        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("privacy record list limit must be non-negative")
        d, _ = _validated_private_directory(self._dir(), must_exist=False)
        if not d.exists():
            return []
        candidates: list[tuple[Path, os.stat_result]] = []
        for path in d.glob("*.json"):
            try:
                info = path.lstat()
            except OSError as exc:
                raise PermissionError(
                    f"privacy record path could not be inspected: {path}"
                ) from exc
            record_id = path.stem
            if (
                _unsafe_path_alias(path, info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not _RECORD_ID_RE.fullmatch(record_id)
                or not record_id.startswith(f"{self.prefix}-")
                or not private_path_is_restricted(path, 0o600)
            ):
                raise PermissionError(
                    "privacy record scan found an invalid record path"
                )
            if info.st_size > _MAX_PRIVACY_JSON_BYTES + _MAX_PRIVACY_ENVELOPE_BYTES:
                raise PrivacyStateError(
                    "privacy record payload exceeds the size limit"
                )
            candidates.append((path, info))
        candidates.sort(
            key=lambda item: (-item[1].st_mtime_ns, item[0].name),
        )
        out = []
        for path, _info in candidates[:limit]:
            with cross_process_lock(path, strict=True):
                record = self._read_path(path)
            if record is not None:
                out.append(record)
        return sorted(out, key=lambda r: r.get("created_at", 0), reverse=True)

    def count_records(self) -> int:
        """Count valid record paths without deserializing an unbounded store."""

        from .file_lock import private_path_is_restricted

        directory, _ = _validated_private_directory(self._dir(), must_exist=False)
        if not directory.exists():
            return 0
        count = 0
        for path in directory.glob("*.json"):
            try:
                info = path.lstat()
            except OSError as exc:
                raise PermissionError(
                    f"privacy record path could not be inspected: {path}"
                ) from exc
            record_id = path.stem
            if (
                _unsafe_path_alias(path, info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not _RECORD_ID_RE.fullmatch(record_id)
                or not record_id.startswith(f"{self.prefix}-")
                or not private_path_is_restricted(path, 0o600)
                or info.st_size > _MAX_PRIVACY_JSON_BYTES + _MAX_PRIVACY_ENVELOPE_BYTES
            ):
                raise PermissionError(
                    "privacy record scan found an invalid record path"
                )
            count += 1
        return count

    def iter_record_ids(
        self,
        *,
        start_after: str = "",
        limit: int = 100,
    ):
        """Yield a rotating, bounded window of validated record identities.

        Directory enumeration may inspect names, but this method deliberately
        performs no record reads and acquires no per-record locks.  Callers can
        therefore put a hard budget on expensive/contended reads while a cursor
        prevents a large store's lexical prefix from starving later records.
        """
        d, _ = _validated_private_directory(self._dir(), must_exist=False)
        if not d.exists():
            return
        paths = sorted(
            (path for path in d.iterdir() if path.name.endswith(".json")),
            key=lambda path: path.name,
        )
        if not paths:
            return
        cursor = str(start_after or "")
        pivot = next(
            (index for index, path in enumerate(paths) if path.name > cursor),
            len(paths),
        )
        ordered = paths[pivot:] + paths[:pivot]
        for path in ordered[:max(0, int(limit))]:
            try:
                info = path.lstat()
            except OSError as exc:
                raise PermissionError(
                    f"privacy record path could not be inspected: {path}"
                ) from exc
            record_id = path.stem
            if (
                _unsafe_path_alias(path, info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not _RECORD_ID_RE.fullmatch(record_id)
                or not record_id.startswith(f"{self.prefix}-")
            ):
                raise PermissionError(
                    "privacy record scan found an invalid record path"
                )
            yield path.name, record_id

    def update(
        self,
        record_id: str,
        mutate,
        *,
        expected_revision: int | None = None,
        metadata_only: bool = False,
        effect_guard=None,
    ) -> dict | None:
        """Run ``mutate`` under the per-record lock and publish if changed.

        ``metadata_only`` is reserved for durable audit-outbox bookkeeping: it
        atomically rewrites the receipt without changing the logical record
        revision that the signed event and client CAS are bound to.
        """
        from .file_lock import cross_process_lock, ensure_private_directory

        path = self._path(record_id)
        if path is None:
            return None
        ensure_private_directory(path.parent)
        _validated_private_directory(path.parent, must_exist=True)
        with cross_process_lock(path, strict=True):
            record = self._read_path(path)
            if record is None:
                return None
            current_revision = self._revision(record)
            expected = self._expected_revision(expected_revision)
            if expected is not None and current_revision != expected:
                raise RecordConflict(
                    f"privacy record changed (expected revision "
                    f"{expected_revision}, found {current_revision})"
                )
            updated = dict(record)
            mutate(updated)
            if updated == record:
                return record
            return self._write_path(
                path,
                updated,
                record,
                bump_revision=not metadata_only,
                effect_guard=effect_guard,
            )


def _actor_label(actor: str = "") -> str:
    """Bounded, collision-resistant durable label for an exact identity."""
    identity = str(actor or "")
    if len(identity) <= 256:
        return identity
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"{identity[:183]}#sha256:{digest}"


def _pending_audit(action: str, actor: str = "") -> dict:
    """A durable, non-PII outbox receipt embedded in the mutated record."""
    return {
        "event_id": uuid.uuid4().hex,
        "action": str(action)[:64],
        "actor": _actor_label(actor) or "system",
        "prepared_at": time.time(),
    }


def _queue_audit(record: dict, action: str, actor: str = "") -> None:
    """Append an event to a record's durable outbox without losing a racer."""
    queue = _validated_audit_queue(record)
    if len(queue) >= _MAX_AUDIT_PENDING_RECEIPTS:
        # Never discard an older receipt to make a new mutation appear
        # auditable. The surrounding locked update aborts without publishing
        # any of the caller's changes.
        raise AuditOutboxError("privacy audit outbox is full")
    queue.append(_pending_audit(action, actor))
    record["_audit_pending"] = queue


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "RecordConflict",
]
