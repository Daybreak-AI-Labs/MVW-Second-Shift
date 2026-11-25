"""Several web workers still have one owner of timers and admission limits."""
from __future__ import annotations

import asyncio
import multiprocessing
import os
from pathlib import Path
from queue import Empty

import pytest


def _leader(root, notices):
    from maverick_dashboard.worker_coordination import lead_timers

    async def heartbeat():
        notices.put(os.getpid())
        await asyncio.Future()

    asyncio.run(lead_timers(Path(root), (heartbeat,), interval=0.03))


def _hold_slots(root, count, notices, finish):
    from maverick_dashboard.worker_coordination import take_slot

    held = [take_slot(Path(root), "admitted-test", 4) for _ in range(count)]
    notices.put(sum(value is not None for value in held))
    finish.wait(10)
    for value in held:
        if value is not None:
            value.release()


def test_only_one_process_runs_the_timers_and_another_takes_over(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    notices = ctx.Queue()
    first = ctx.Process(target=_leader, args=(str(tmp_path), notices))
    second = ctx.Process(target=_leader, args=(str(tmp_path), notices))
    try:
        first.start()
        assert notices.get(timeout=10) == first.pid
        second.start()
        with pytest.raises(Empty):
            notices.get(timeout=0.5)
        first.kill()
        first.join(5)
        assert notices.get(timeout=10) == second.pid
    finally:
        for process in (first, second):
            if process.is_alive():
                process.kill()
            if process.pid:
                process.join(5)
        notices.close()


def test_admission_limit_is_shared_and_worker_exit_frees_its_slots(tmp_path):
    from maverick_dashboard.worker_coordination import take_slot

    ctx = multiprocessing.get_context("spawn")
    notices = ctx.Queue()
    finish = ctx.Event()
    first = ctx.Process(target=_hold_slots, args=(str(tmp_path), 3, notices, finish))
    second = ctx.Process(target=_hold_slots, args=(str(tmp_path), 3, notices, finish))
    try:
        first.start()
        assert notices.get(timeout=10) == 3
        second.start()
        assert notices.get(timeout=10) == 1
        assert take_slot(tmp_path, "admitted-test", 4) is None
        first.kill()
        first.join(5)
        held = take_slot(tmp_path, "admitted-test", 4)
        assert held is not None
        held.release()
    finally:
        finish.set()
        for process in (first, second):
            if process.pid:
                process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
        notices.close()
