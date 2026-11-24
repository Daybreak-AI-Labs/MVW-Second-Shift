"""Established-socket ownership; real loopback PostgreSQL where configured."""
from __future__ import annotations

import importlib
import socket
import threading
import time
from types import SimpleNamespace

import pytest

psycopg = pytest.importorskip("psycopg")
pg_io = importlib.import_module("maverick.postgres_io")
BoundedConnection = pg_io.BoundedConnection
PostgresIOTimeout = pg_io.PostgresIOTimeout
_deadline_generator = pg_io._deadline_generator
Wait = psycopg.waiting.Wait


@pytest.fixture
def pools(monkeypatch):
    yield


def test_deadline_generator_preserves_readiness_and_return_and_closes():
    observed = []
    def query():
        try:
            observed.append((yield Wait.R))
            observed.append((yield Wait.W))
            return "query-result"
        finally:
            observed.append("closed")
    owned = _deadline_generator(query(), time.monotonic() + 1)
    assert next(owned) == Wait.R
    assert owned.send(1) == Wait.W
    with pytest.raises(StopIteration) as done:
        owned.send(2)
    assert done.value.value == "query-result" and observed == [1, 2, "closed"]


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_real_readiness_wait_times_out_and_closes_only_on_owner_thread(cleanup_fails):
    observed = []
    caller = threading.get_ident()
    def query():
        try:
            while True:
                observed.append((yield Wait.R))
        finally:
            observed.append("generator-closed")
    # Retain the peer: this is an established socket with no response, not EOF.
    waiting_socket, peer = socket.socketpair()
    try:
        closes = []
        def close():
            closes.append(threading.get_ident())
            waiting_socket.close()
            if cleanup_fails:
                raise OSError("fixture cleanup failure")
        connection = SimpleNamespace(_io_timeout_seconds=.15, pgconn=SimpleNamespace(socket=waiting_socket.fileno()), close=close)
        started = time.monotonic()
        with pytest.raises(PostgresIOTimeout) as error:
            BoundedConnection.wait(connection, query(), interval=0)
        assert .12 <= time.monotonic() - started < 1
        assert error.value.outcome_unknown and closes == [caller]
        assert observed[-1] == "generator-closed"
        assert bool(getattr(error.value, "cleanup_incomplete", False)) is cleanup_fails
    finally:
        waiting_socket.close()
        peer.close()


def test_keyboard_interrupt_closes_owned_socket_without_cancel_request():
    stop = KeyboardInterrupt()
    closed = []
    def query():
        raise stop
        yield Wait.R
    with socket.socket() as sock:
        connection = SimpleNamespace(_io_timeout_seconds=1, pgconn=SimpleNamespace(socket=sock.fileno()),
                                     close=lambda: closed.append(threading.get_ident()))
        with pytest.raises(KeyboardInterrupt) as error:
            BoundedConnection.wait(connection, query())
    assert error.value is stop and closed == [threading.get_ident()]


@pytest.mark.parametrize("kind", ["deadline", "interrupt"])
def test_generator_cleanup_failure_preserves_primary_and_closes_socket(monkeypatch, kind):
    stop = KeyboardInterrupt("fixture control stop")
    cleanup = RuntimeError("fixture generator cleanup failure")
    clock = [0.0]
    monkeypatch.setattr(pg_io.time, "monotonic", lambda: clock[0])

    class Query:
        def __next__(self):
            if kind == "interrupt":
                raise stop
            return Wait.R

        def close(self):
            raise cleanup

    def wait(generator, sock, interval):
        next(generator)
        clock[0] = 2.0
        generator.send(0)

    monkeypatch.setattr(pg_io.waiting, "wait", wait)
    closes = []
    connection = SimpleNamespace(_io_timeout_seconds=1, pgconn=SimpleNamespace(socket=-1),
                                 close=lambda: closes.append(threading.get_ident()))
    with pytest.raises(PostgresIOTimeout if kind == "deadline" else KeyboardInterrupt) as error:
        BoundedConnection.wait(connection, Query())
    if kind == "interrupt":
        assert error.value is stop
    assert error.value is not cleanup
    assert error.value.cleanup_incomplete and error.value.outcome_unknown
    assert closes == [threading.get_ident()]


@pytest.mark.parametrize("kind", ["deadline", "interrupt", "driver", "success"])
@pytest.mark.parametrize("connection_close_fails", [False, True])
def test_final_wrapper_cleanup_cannot_replace_primary(monkeypatch, kind, connection_close_fails):
    primary = {"deadline": PostgresIOTimeout("fixture deadline"), "interrupt": KeyboardInterrupt(),
               "driver": RuntimeError("fixture driver failure"), "success": None}[kind]
    cleanup = RuntimeError("fixture wrapper close failure")

    def close_generator():
        raise cleanup

    def wait(generator, sock, interval):
        if primary is not None:
            raise primary
        return "completed"

    monkeypatch.setattr(pg_io, "_deadline_generator", lambda *_args: SimpleNamespace(close=close_generator))
    monkeypatch.setattr(pg_io.waiting, "wait", wait)
    closes = []

    def close_connection():
        closes.append(threading.get_ident())
        if connection_close_fails:
            raise OSError("fixture connection cleanup failure")

    connection = SimpleNamespace(_io_timeout_seconds=1, pgconn=SimpleNamespace(socket=-1), close=close_connection)
    authoritative = primary if primary is not None else cleanup
    with pytest.raises(type(authoritative)) as error:
        BoundedConnection.wait(connection, object())
    assert error.value is authoritative
    assert error.value.cleanup_incomplete and error.value.outcome_unknown
    assert closes == [threading.get_ident()]
