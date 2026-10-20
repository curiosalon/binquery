"""Input contract validation, independent of loaders and symbolic engines."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class Invalid(ValueError):
    """The supplied contract is malformed or contradictory."""


class Unsupported(RuntimeError):
    """An operation is outside this backend's qualified subset."""


class Incomplete(RuntimeError):
    """Analysis cannot cover the entire declared domain."""


def number(value):
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise Invalid(f"Invalid integer: {value!r}") from exc
    if type(value) is not int:
        raise Invalid(f"Expected integer or prefixed integer string: {value!r}")
    return value


def fields(value, allowed, required=()):
    if not isinstance(value, dict):
        raise Invalid("Expected an object")
    if set(value) - set(allowed) or set(required) - set(value):
        raise Invalid(
            f"Unexpected/missing fields: {sorted(set(value) - set(allowed))}; "
            f"{sorted(set(required) - set(value))}"
        )


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_flags(value):
    # Arithmetic flags, IF and DF only. The model has no trap, VM86, alignment
    # checking or privilege transition semantics. Reserved bit 1 must be set.
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise Invalid("Flags are outside 32 bits")
    if value & ~0xED7 or not value & 2:
        raise Unsupported(
            "Flags require reserved bit 1 and only arithmetic, IF and DF bits"
        )


def contract(path):
    source = Path(path).resolve()
    raw = source.read_bytes()
    d = json.loads(raw)
    fields(
        d,
        {
            "schema",
            "format",
            "architecture",
            "entry",
            "code",
            "stops",
            "registers",
            "flags",
            "memory",
            "claims",
            "limits",
            "a20",
            "shift_count",
        },
        {"schema", "entry", "code", "stops", "registers", "flags"},
    )
    if d["schema"] != 1:
        raise Invalid("Only schema 1 is supported")
    d["format"] = d.get("format", "blob")
    if d["format"] not in ("blob", "auto"):
        raise Unsupported("Input format must be blob or auto")
    if d["format"] == "blob" and "architecture" not in d:
        raise Invalid("Raw input needs an explicit architecture")
    d["entry"] = number(d["entry"])
    d["flags"] = number(d["flags"])
    validate_flags(d["flags"])
    if not isinstance(d["registers"], dict):
        raise Invalid("registers must be an object")
    for name, value in list(d["registers"].items()):
        if not isinstance(name, str) or name != name.lower():
            raise Invalid("Use lowercase register names")
        if isinstance(value, dict):
            fields(value, {"symbolic", "min", "max"}, {"symbolic"})
            if value["symbolic"] is not True:
                raise Invalid("symbolic must be true")
            for key in ("min", "max"):
                if key in value:
                    value[key] = number(value[key])
        else:
            d["registers"][name] = number(value)
    if not isinstance(d["code"], list) or not d["code"]:
        raise Invalid("An explicit, nonempty code range list is required")
    if len(d["code"]) > 128:
        raise Invalid("At most 128 code ranges")
    for row in d["code"]:
        fields(
            row, {"file", "offset", "address", "size", "sha256"}, {"address", "size"}
        )
        for key in ("address", "size"):
            row[key] = number(row[key])
        row["offset"] = number(row.get("offset", 0))
        if row["address"] < 0 or row["offset"] < 0 or not 0 < row["size"] <= 1048576:
            raise Invalid("Invalid code range")
        if "file" in row:
            row["file"] = str((source.parent / row["file"]).resolve())
        if d["format"] == "auto" and ("file" in row or row["offset"]):
            raise Invalid("Auto format ranges use loaded virtual addresses only")
    spans = sorted((r["address"], r["address"] + r["size"]) for r in d["code"])
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise Invalid("Overlapping code ranges")
    if not isinstance(d["stops"], list) or not d["stops"]:
        raise Invalid("Explicit stop addresses are required")
    for row in d["stops"]:
        fields(row, {"address", "kind"}, {"address", "kind"})
        row["address"] = number(row["address"])
        if row["kind"] not in ("return", "failure", "boundary"):
            raise Invalid("Stop kind must be return, failure or boundary")
        if any(lo <= row["address"] < hi for lo, hi in spans):
            raise Invalid("A stop cannot hide instructions inside a code range")
    if len({r["address"] for r in d["stops"]}) != len(d["stops"]):
        raise Invalid("Duplicate stop")
    d["memory"] = d.get("memory", [])
    if not isinstance(d["memory"], list):
        raise Invalid("memory must be a list")
    memory_spans = []
    for row in d["memory"]:
        fields(row, {"address", "hex", "symbolic", "size", "min", "max"}, {"address"})
        row["address"] = number(row["address"])
        if ("hex" in row) == ("symbolic" in row):
            raise Invalid("Memory needs exactly one of hex or symbolic")
        if "hex" in row:
            if set(row) != {"address", "hex"}:
                raise Invalid("Concrete memory takes only address and hex")
            try:
                size = len(bytes.fromhex(row["hex"]))
            except (ValueError, TypeError) as exc:
                raise Invalid("Invalid memory hex") from exc
        else:
            if row["symbolic"] is not True:
                raise Invalid("symbolic must be true")
            row["size"] = size = number(row.get("size", 1))
            for key in ("min", "max"):
                if key in row:
                    row[key] = number(row[key])
            if ("min" in row or "max" in row) and size not in (1, 2, 4, 8):
                raise Invalid("Bounded memory scalars have sizes 1, 2, 4 or 8")
        if row["address"] < 0 or not 0 < size <= 65536:
            raise Invalid("Invalid memory range")
        memory_spans.append((row["address"], row["address"] + size))
    all_spans = sorted(spans + memory_spans)
    if any(a[1] > b[0] for a, b in zip(all_spans, all_spans[1:])):
        raise Invalid("Overlapping initial memory/code declarations")
    d["claims"] = d.get("claims", [])
    if not isinstance(d["claims"], list):
        raise Invalid("claims must be a list")
    for row in d["claims"]:
        fields(row, {"name", "kind", "register", "value", "instruction"}, {"kind"})
        kind = row["kind"]
        if kind not in ("preserved", "return_equals", "no_read"):
            raise Unsupported(f"Claim kind {kind}")
        required = (
            {"register"}
            if kind == "preserved"
            else {"register", "value"}
            if kind == "return_equals"
            else {"instruction"}
        )
        if not required <= row.keys() or set(row) - required - {"name", "kind"}:
            raise Invalid(f"Invalid fields for claim {kind}")
        for key in ("value", "instruction"):
            if key in row:
                row[key] = number(row[key])
    defaults = {
        "steps": 128,
        "states": 256,
        "seconds": 30,
        "solver_ms": 5000,
        "addresses": 32,
    }
    given = d.get("limits", {})
    fields(given, defaults)
    limits = defaults | {k: number(v) for k, v in given.items()}
    maxima = {
        "steps": 4096,
        "states": 4096,
        "seconds": 300,
        "solver_ms": 60000,
        "addresses": 256,
    }
    if any(not 0 < v <= maxima[k] for k, v in limits.items()):
        raise Invalid("Limits must be positive and within documented caps")
    d["limits"] = limits
    d["a20"] = d.get("a20", True)
    if type(d["a20"]) is not bool:
        raise Invalid("a20 must be boolean")
    d["shift_count"] = d.get("shift_count", "portable")
    if d["shift_count"] not in ("portable", "masked5"):
        raise Unsupported(
            "shift_count must be portable or masked5; unmasked 8086 shifts above 31 are not qualified"
        )
    return d, {"path": str(source), "sha256": digest(raw)}
