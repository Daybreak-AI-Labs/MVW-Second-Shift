"""Different recorders may progress together while a control change waits."""
from __future__ import annotations

import multiprocessing

import pytest


def _reader(home, entered, released):
    from maverick.file_lock import cross_process_lock

    with cross_process_lock(home / "ekko-policy", strict=True, shared=True):
        entered.set()
        released.wait(timeout=10)


def _writer(home, entered):
    from maverick.file_lock import cross_process_lock

    with cross_process_lock(home / "ekko-policy", strict=True):
        entered.set()


def test_shared_recorders_finish_before_the_control_change(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    entered = [ctx.Event(), ctx.Event(), ctx.Event()]
    releases = [ctx.Event(), ctx.Event()]
    reader_a = ctx.Process(target=_reader, args=(tmp_path, entered[0], releases[0]))
    reader_b = ctx.Process(target=_reader, args=(tmp_path, entered[1], releases[1]))
    writer = ctx.Process(target=_writer, args=(tmp_path, entered[2]))
    try:
        reader_a.start()
        assert entered[0].wait(5)
        reader_b.start()
        assert entered[1].wait(5)
        writer.start()
        assert not entered[2].wait(.2)
        releases[0].set()
        assert not entered[2].wait(.2)
        releases[1].set()
        assert entered[2].wait(5)
    finally:
        for release in releases:
            release.set()
        for process in (reader_a, reader_b, writer):
            if process.pid:
                process.join(2)
            if process.is_alive():
                process.kill()
                process.join(2)


def test_shared_control_cannot_be_upgraded_in_place(tmp_path):
    from maverick.file_lock import cross_process_lock

    path = tmp_path / "ekko-policy"
    with cross_process_lock(path, strict=True, shared=True):
        with pytest.raises(RuntimeError, match="upgrade"):
            with cross_process_lock(path, strict=True):
                pass
