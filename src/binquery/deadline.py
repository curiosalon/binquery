"""Enforce CLI deadlines outside the analysis process on every host OS."""

import json
import subprocess
import sys

from .model import Incomplete


def run_bounded(arguments, seconds):
    # Isolated mode excludes the target directory and PYTHONPATH from imports.
    # The child runs only our installed Python worker, never the input binary.
    # communicate() drains both pipes while waiting; large witnesses cannot
    # deadlock a join-before-read protocol. Timeout kills and reaps the child.
    try:
        done = subprocess.run(
            [sys.executable, "-I", "-m", "binquery._worker"],
            input=json.dumps(arguments),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise Incomplete("Wall clock deadline reached") from exc
    if done.stderr:
        sys.stderr.write(done.stderr)
    if done.returncode:
        raise RuntimeError(f"Analysis worker exited with status {done.returncode}")
    try:
        result = json.loads(done.stdout)
    except ValueError as exc:
        raise RuntimeError("Analysis worker returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise RuntimeError("Analysis worker returned no result object")
    return result
