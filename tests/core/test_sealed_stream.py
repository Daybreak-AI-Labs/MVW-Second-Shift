"""Authenticated frame boundaries; never treat a suffix as whole-file proof."""
from __future__ import annotations

import io
import struct

import pytest

from maverick import crypto_at_rest as crypto
from maverick.sealed_stream import STREAM_MAGIC, FramedReader, SealedStreamError


@pytest.fixture(autouse=True)
def keys(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "11" * 32)
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "fixture-at-rest.key")


def test_plaintext_and_nested_manifest_envelopes_refused():
    for unsealed in (b'{"version":1}', STREAM_MAGIC + b"fake"):
        raw = STREAM_MAGIC + struct.pack(">I", len(unsealed)) + unsealed
        with pytest.raises(SealedStreamError, match="manifest"):
            FramedReader(io.BytesIO(raw), crypto.unseal)
