import base64
import json
import threading

import httpx
import pytest

from second_shift_runtime.loop import RunResult
from second_shift_runtime.server import make_server
from second_shift_runtime.skills import FileInfo


class Served:
    def __init__(self, runner, tmp_path, **kw):
        self.server = make_server(runner, "127.0.0.1", 0, tmp_path / "out", **kw)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def serve(tmp_path):
    started = []

    def start(runner, **kw):
        s = Served(runner, tmp_path, **kw)
        started.append(s)
        return s

    yield start
    for s in started:
        s.close()


def ok_runner(prompt, output_dir):
    return RunResult(outcome="success", answer=f"echo: {prompt}", steps=1, input_tokens=5, output_tokens=2, cost_dollars=0.01, report_sent=True)


def test_ping_reports_healthy(serve):
    s = serve(ok_runner)
    r = httpx.get(s.url + "/ping")
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    assert r.json()["status"] == "Healthy" and isinstance(r.json()["time_of_last_update"], int)


def test_invocation_returns_the_answer_in_the_agentcore_shape(serve):
    s = serve(ok_runner)
    r = httpx.post(s.url + "/invocations", json={"prompt": "hello"})
    body = r.json()
    assert r.status_code == 200 and body["response"] == "echo: hello" and body["status"] == "success"
    assert body["usage"] == {"steps": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 2, "estimated_cost_dollars": 0.01}
    assert httpx.post(s.url + "/invocations", json={"input": "also fine"}).json()["response"] == "echo: also fine"


def test_a_failed_run_is_a_200_with_status_failure_and_the_reason(serve):
    s = serve(lambda p, d: RunResult(outcome="failure", reason="Second Shift did not allow fetch_web_page: no"))
    body = httpx.post(s.url + "/invocations", json={"prompt": "x"}).json()
    assert body["status"] == "failure" and body["reason"].startswith("Second Shift did not allow") and body["response"] == body["reason"]


def test_files_come_back_with_name_size_hash_and_content(serve, tmp_path):
    def runner(prompt, output_dir):
        output_dir.mkdir(parents=True)
        path = output_dir / "a.txt"
        path.write_bytes(b"hello file")
        return RunResult(outcome="success", answer="made", files=[FileInfo("a.txt", 10, "h" * 64, path)])

    s = serve(runner)
    entry = httpx.post(s.url + "/invocations", json={"prompt": "x"}).json()["files"][0]
    assert entry["name"] == "a.txt" and entry["size"] == 10 and base64.b64decode(entry["content_base64"]) == b"hello file"


def test_each_invocation_gets_its_own_output_folder(serve, tmp_path):
    seen = []
    s = serve(lambda p, d: (seen.append(d), RunResult(outcome="success", answer="x"))[1])
    httpx.post(s.url + "/invocations", json={"prompt": "1"})
    httpx.post(s.url + "/invocations", json={"prompt": "2"})
    assert seen[0] != seen[1] and seen[0].parent == tmp_path / "out"


@pytest.mark.parametrize("payload,status", [
    (b"not json", 400), (b"[]", 400), (b'{"prompt": ""}', 400), (b'{"prompt": 5}', 400), (b'{"other": "x"}', 400),
])
def test_bad_requests_are_refused_in_plain_words(serve, payload, status):
    s = serve(lambda p, d: pytest.fail("must not run"))
    r = httpx.post(s.url + "/invocations", content=payload)
    assert r.status_code == status and "prompt" in r.json()["error"]


def test_oversized_and_unknown_paths(serve):
    s = serve(lambda p, d: pytest.fail("must not run"))
    assert httpx.post(s.url + "/invocations", content=b"x" * 1_000_001).status_code == 413
    assert httpx.get(s.url + "/nothing").status_code == 404
    assert httpx.post(s.url + "/ping", content=b"{}").status_code == 404
    assert httpx.get(s.url + "/invocations").status_code == 404


def test_an_optional_inbound_bearer_key_protects_invocations_but_not_ping(serve):
    s = serve(ok_runner, inbound_key="let-me-in")
    assert httpx.get(s.url + "/ping").status_code == 200
    assert httpx.post(s.url + "/invocations", json={"prompt": "x"}).status_code == 401
    assert httpx.post(s.url + "/invocations", json={"prompt": "x"}, headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = httpx.post(s.url + "/invocations", json={"prompt": "x"}, headers={"Authorization": "Bearer let-me-in"})
    assert r.status_code == 200 and "let-me-in" not in r.text


def test_a_crashing_runner_is_a_500_without_details(serve):
    def boom(prompt, d):
        raise RuntimeError("secret internals")

    s = serve(boom)
    r = httpx.post(s.url + "/invocations", json={"prompt": "x"})
    assert r.status_code == 500 and "secret" not in r.text


def test_busy_status_and_the_concurrency_limit(serve):
    started, release = threading.Event(), threading.Event()

    def slow(prompt, d):
        started.set()
        release.wait(5)
        return RunResult(outcome="success", answer="slow done")

    s = serve(slow, max_concurrent=1)
    first = {}
    t = threading.Thread(target=lambda: first.update(r=httpx.post(s.url + "/invocations", json={"prompt": "a"}, timeout=10)))
    t.start()
    assert started.wait(5)
    assert httpx.get(s.url + "/ping").json()["status"] == "HealthyBusy"
    busy = httpx.post(s.url + "/invocations", json={"prompt": "b"})
    assert busy.status_code == 429 and busy.headers["retry-after"] == "5"
    release.set()
    t.join(5)
    assert first["r"].json()["response"] == "slow done"
    assert httpx.get(s.url + "/ping").json()["status"] == "Healthy"


def test_the_definition_runner_runs_a_governed_run(tmp_path, monkeypatch):
    from second_shift_runtime import server
    from second_shift_runtime.definition import parse_definition

    from fakes import definition_dict

    seen = {}
    monkeypatch.setattr(server, "run_agent", lambda d, p, out: (seen.update(d=d, p=p, out=out), RunResult(outcome="success", answer="ok"))[1])
    result = server.definition_runner(parse_definition(definition_dict()))("task", tmp_path)
    assert result.answer == "ok" and seen["p"] == "task" and seen["out"] == tmp_path
    json.dumps(server.result_body(result))
