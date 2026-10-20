import json
import subprocess
import sys

import pytest

from binquery.deadline import run_bounded
from binquery.model import Incomplete
from binquery.discovery import example


def arguments(tmp_path):
    binary = tmp_path / "nop.bin"
    binary.write_bytes(b"\x90")
    spec = tmp_path / "model.json"
    spec.write_text(json.dumps(example("real16")))
    return {
        "command": "query",
        "binary": str(binary),
        "contract": str(spec),
        "json": True,
    }


def test_portable_worker_result(tmp_path):
    result = run_bounded(arguments(tmp_path), 30)
    assert result["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"


def test_portable_deadline_terminates_worker(tmp_path):
    with pytest.raises(Incomplete, match="Wall clock deadline"):
        run_bounded(arguments(tmp_path), 0.001)


def test_cli_deadline_is_inconclusive(tmp_path):
    args = arguments(tmp_path)
    from pathlib import Path

    path = Path(args["contract"])
    spec = json.loads(path.read_text())
    spec["limits"]["seconds"] = 1
    spec["limits"]["steps"] = 4096
    Path(args["binary"]).write_bytes(bytes.fromhex("ebfe"))
    spec["code"][0]["size"] = 2
    spec["stops"][0]["address"] = spec["entry"] + 2
    path.write_text(json.dumps(spec))
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "query",
            args["binary"],
            "--contract",
            str(path),
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert done.returncode == 2
    assert json.loads(done.stdout)["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("returncode,stdout", [(1, "{}"), (0, "bad"), (0, "[]")])
def test_worker_failure_is_not_proof(monkeypatch, returncode, stdout):
    def failed(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], returncode, stdout, "")

    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(RuntimeError):
        run_bounded({}, 1)


def test_worker_ignores_target_directory_and_pythonpath(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    package = tmp_path / "binquery"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "_worker.py").write_text(
        "from pathlib import Path\n"
        "Path('untrusted-worker-ran').write_text('yes')\n"
        "print('{}')\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    result = run_bounded(args, 30)
    assert result["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"
    assert not (tmp_path / "untrusted-worker-ran").exists()
