import json

import pytest

from second_shift_runtime import __main__ as cli
from second_shift_runtime.loop import RunResult
from second_shift_runtime.skills import FileInfo

from fakes import definition_dict


@pytest.fixture
def definition_file(tmp_path):
    path = tmp_path / "agent.json"
    path.write_text(json.dumps(definition_dict()))
    return str(path)


def test_run_prints_the_answer_and_lists_files(definition_file, tmp_path, monkeypatch, capsys):
    seen = {}

    def fake(definition, task, output):
        seen.update(task=task, output=output)
        return RunResult(outcome="success", answer="the answer", files=[FileInfo("a.docx", 3, "h", tmp_path / "a.docx")])

    monkeypatch.setattr(cli, "run_agent", fake)
    assert cli.main(["run", "--definition", definition_file, "--input", "do it", "--output", str(tmp_path / "o")]) == 0
    out = capsys.readouterr()
    assert out.out == "the answer\n" and "a.docx" in out.err and seen["task"] == "do it" and str(seen["output"]) == str(tmp_path / "o")


def test_run_failure_exits_non_zero_with_the_reason(definition_file, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_agent", lambda *a: RunResult(outcome="failure", reason="Second Shift did not allow x", report_error="gone"))
    assert cli.main(["run", "--definition", definition_file, "--input", "x"]) == 1
    err = capsys.readouterr().err
    assert "did not finish: Second Shift did not allow x" in err and "could not be sent" in err


def test_run_reads_the_task_from_standard_input(definition_file, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("from stdin"))
    monkeypatch.setattr(cli, "run_agent", lambda d, task, out: RunResult(outcome="success", answer=task))
    assert cli.main(["run", "--definition", definition_file, "--input", "-"]) == 0
    assert capsys.readouterr().out == "from stdin\n"


def test_a_bad_definition_exits_with_a_plain_message(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({**definition_dict(), "extra": 1}))
    assert cli.main(["run", "--definition", str(path), "--input", "x"]) == 2
    err = capsys.readouterr().err
    assert "cannot be used" in err and "unknown field 'extra'" in err


def test_serve_needs_its_inbound_key_when_one_is_named(definition_file, monkeypatch, capsys):
    monkeypatch.delenv("INBOUND", raising=False)
    assert cli.main(["serve", "--definition", definition_file, "--inbound-key-env", "INBOUND"]) == 2
    assert "INBOUND is empty" in capsys.readouterr().err


def test_serve_starts_and_stops(definition_file, monkeypatch):
    started = {}

    class Fake:
        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            started["closed"] = True

    monkeypatch.setattr(cli, "make_server", lambda runner, host, port, out, inbound_key=None: started.update(port=port, key=inbound_key) or Fake())
    monkeypatch.setenv("INBOUND", "k")
    assert cli.main(["serve", "--definition", definition_file, "--port", "9", "--inbound-key-env", "INBOUND"]) == 0
    assert started == {"port": 9, "key": "k", "closed": True}
