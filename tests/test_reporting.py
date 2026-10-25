"""Local report lifecycle and command isolation."""

import json
import os
from pathlib import Path
import subprocess
import sys


HELPER = Path(__file__).resolve().parents[1] / "skills/binquery/scripts/report_issue.py"


def call(*args, env=None):
    return subprocess.run(
        [sys.executable, str(HELPER), *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


def test_report_lifecycle_never_runs_supplied_command(tmp_path):
    marker = tmp_path / "must-not-exist"
    request = tmp_path / "request.json"
    data = dict(
        title="Unexpected failure",
        cwd=str(tmp_path),
        kind="bug",
        impact="blocker",
        binquery_version="0.8.2",
        expected="Complete",
        actual="Error",
        argv=[sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
        evidence=["result.json"],
        environment={"os": "test"},
    )
    request.write_text(json.dumps(data), encoding="utf-8")
    queue = tmp_path / "queue"
    first = call("submit", request, "--directory", queue)
    assert first.returncode == 0, first.stderr
    saved = Path(first.stdout.strip())
    report = json.loads(saved.read_text(encoding="utf-8"))
    assert report["request"] == data
    assert not marker.exists()
    if os.name != "nt":
        assert saved.stat().st_mode & 0o777 == 0o600
    second = call("submit", request, "--directory", queue)
    assert second.returncode == 0 and second.stdout != first.stdout
    assert len(json.loads(call("list", "--directory", queue).stdout)) == 2
    resolved = call(
        "resolve",
        report["id"],
        "--directory",
        queue,
        "--summary",
        "Fixed and tested",
        "--version",
        "0.8.3",
        "--evidence",
        "test.log",
    )
    assert resolved.returncode == 0, resolved.stderr
    final = json.loads(saved.read_text(encoding="utf-8"))
    assert final["request"] == data and final["state"] == "resolved"
    assert final["resolution"]["evidence"] == ["test.log"]
    assert len(json.loads(call("list", "--directory", queue).stdout)) == 1
    assert (
        call(
            "resolve",
            "../escape",
            "--directory",
            queue,
            "--summary",
            "x",
            "--version",
            "x",
        ).returncode
        == 2
    )


def test_invalid_report_does_not_create_queue_and_env_selects_location(tmp_path):
    request = tmp_path / "bad.json"
    request.write_text('{"title": "Missing reproduction"}', encoding="utf-8")
    queue = tmp_path / "queue"
    env = dict(os.environ, BINQUERY_REPORT_DIR=str(queue))
    result = call("submit", request, env=env)
    assert result.returncode == 2
    assert not queue.exists()
    assert json.loads(call("list", env=env).stdout) == []
