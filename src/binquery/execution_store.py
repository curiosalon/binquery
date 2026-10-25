"""One atomic local checkpoint with separately readable portable JSON."""

from __future__ import annotations

import functools
import importlib.metadata
import io
import json
import operator
import os
import pickle
import platform
import tempfile
import zipfile
from pathlib import Path

from .model import Incomplete, Invalid, digest

_NARY = {
    "__add__": operator.add,
    "__mul__": operator.mul,
    "__and__": operator.and_,
    "__or__": operator.or_,
    "__xor__": operator.xor,
    "And": operator.and_,
    "Or": operator.or_,
}


def _restore_nary(operation, args, annotations):
    result = functools.reduce(_NARY[operation], args)
    return result.annotate(*annotations) if annotations else result


class StatePickler(pickle.Pickler):
    def reducer_override(self, value):
        # Pinned clarirs' AST constructor restores only two operands of n-ary
        # arithmetic/Boolean nodes. Keep angr's serializer, repairing that
        # constructor call rather than inventing a symbolic checkpoint format.
        from angr import claripy

        if (
            isinstance(value, (claripy.BV, claripy.Bool))
            and value.op in _NARY
            and len(value.args) > 2
        ):
            return _restore_nary, (value.op, value.args, value.annotations)
        return NotImplemented


def versions():
    from . import __version__

    return {
        "binquery": __version__,
        "python": platform.python_version(),
        "machine": platform.machine(),
        **{
            p: importlib.metadata.version(p)
            for p in (
                "angr",
                "pypcode",
                "unicorn",
                "capstone",
                "archinfo",
                "networkx",
                "z3-solver",
            )
        },
        "implementation": digest(
            b"".join(p.read_bytes() for p in sorted(Path(__file__).parent.glob("*.py")))
        ),
    }


def read_report(path):
    try:
        with zipfile.ZipFile(path) as z:
            if z.getinfo("report.json").file_size > 1024**3:
                raise Invalid("Report exceeds supported size")
            return json.loads(z.read("report.json"))
    except (zipfile.BadZipFile, KeyError, ValueError) as exc:
        raise Invalid(f"Invalid analysis report: {exc}") from exc


def save(execution, path, result):
    path = Path(path).resolve()
    cap = execution.config["limits"]["checkpoint_mb"] * 1024**2

    def clean(rows):
        output = []
        for index, state, *rest in rows:
            s = state.copy()
            s.scratch.irsb = None  # native pypcode instructions are not serializable
            output.append((index, s, *rest))
        return output

    payload = {
        "format": 1,
        "versions": versions(),
        "config": execution.config,
        "pending": clean(execution.pending),
        "finished": clean(execution.finished),
        **{
            k: getattr(execution, k)
            for k in ("elapsed", "steps", "solver_calls", "invocations", "replays")
        },
    }
    stream = io.BytesIO()
    StatePickler(stream, protocol=pickle.HIGHEST_PROTOCOL).dump(payload)
    checkpoint = stream.getvalue()
    if len(checkpoint) > cap:
        raise Incomplete("Checkpoint size limit; previous saved analysis is unchanged")
    result["checkpoint_versions"] = payload["versions"]
    result["metrics"]["checkpoint_bytes"] = len(checkpoint)
    result["checkpoint_trust"] = (
        "Resume only locally created trusted files; report/query/graph never deserialize machine states"
    )
    raw_report = json.dumps(result, indent=2).encode()
    if len(checkpoint) + len(raw_report) > cap:
        raise Incomplete(
            "Checkpoint/report size limit; previous saved analysis is unchanged"
        )
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w+b") as f:
            with zipfile.ZipFile(f, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("report.json", raw_report)
                z.writestr("checkpoint.pickle", checkpoint)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return result


def validate_saved(public):
    if public.get("checkpoint_versions") != versions():
        raise Invalid(
            "Checkpoint engine/tool versions differ; portable report remains readable"
        )
    for file, expected in public["inputs"].items():
        if digest(Path(file).read_bytes()) != expected:
            raise Invalid(
                f"Checkpoint input changed: {file}; portable report remains readable"
            )


def restore(path):
    public = read_report(path)
    validate_saved(public)
    with zipfile.ZipFile(path) as z:
        if z.getinfo("checkpoint.pickle").file_size > 1024**3:
            raise Invalid("Checkpoint exceeds supported size")
        payload = pickle.loads(z.read("checkpoint.pickle"))
    if (
        payload.get("format") != 1
        or payload.get("versions") != versions()
        or payload["config"]["inputs"] != public["inputs"]
    ):
        raise Invalid("Incompatible checkpoint")
    from .execution import Execution

    execution = Execution(payload["config"])
    for name in (
        "pending",
        "finished",
        "elapsed",
        "steps",
        "solver_calls",
        "invocations",
        "replays",
    ):
        setattr(execution, name, payload[name])
    for index, state, *_ in [*execution.pending, *execution.finished]:
        execution.engines[index].install_hooks(state)
    return execution
