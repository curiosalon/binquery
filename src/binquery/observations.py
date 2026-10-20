"""Bounded paired RAM observations, independent of architectural access traces."""

import copy
import json
from pathlib import Path

from .model import Invalid, Unsupported, digest, fields, number

MAX_BYTES = 4096
MAX_REGIONS = 64


def regions(rows, label):
    if not isinstance(rows, list) or len(rows) > MAX_REGIONS:
        raise Invalid(f"{label} needs a list of at most {MAX_REGIONS} regions")
    names = set()
    for row in rows:
        fields(
            row, {"name", "left", "right", "size"}, {"name", "left", "right", "size"}
        )
        if not isinstance(row["name"], str) or not row["name"] or row["name"] in names:
            raise Invalid("Region names must be nonempty and unique")
        names.add(row["name"])
        for k in ("left", "right", "size"):
            row[k] = number(row[k])
        if min(row["left"], row["right"]) < 0 or row["size"] <= 0:
            raise Invalid("Region addresses must be nonnegative and sizes positive")
    if sum(r["size"] for r in rows) > MAX_BYTES:
        raise Invalid(f"{label} exceeds {MAX_BYTES} bytes")
    for side in ("left", "right"):
        spans = sorted((r[side], r[side] + r["size"]) for r in rows)
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise Invalid(f"Overlapping {label} regions on {side}")
    return rows


def comparison_contract(value):
    d = copy.deepcopy(value)
    fields(d, {"schema", "memory", "relation", "pointers"}, {"schema"})
    if type(d["schema"]) is not int or d["schema"] != 1:
        raise Invalid("Comparison contract requires schema 1")
    d["memory"] = regions(d.get("memory", []), "final memory")
    d["pointers"] = pointer_rows(d.get("pointers", []))
    if "relation" in d:
        rel = d["relation"]
        fields(rel, {"regions", "pointers", "stack"}, {"regions"})
        rel["regions"] = regions(rel["regions"], "input relation")
        rel["pointers"] = pointer_rows(rel.get("pointers", []))
        if "stack" in rel:
            fields(rel["stack"], {"address", "size"}, {"address", "size"})
            rel["stack"] = {k: number(v) for k, v in rel["stack"].items()}
            if rel["stack"]["address"] < 0 or not 0 < rel["stack"]["size"] <= 65536:
                raise Invalid(
                    "Stack window needs a nonnegative address and 1..65536 bytes"
                )
    elif d["pointers"]:
        raise Invalid("Pointer observables require an explicit input relation")
    return d


def pointer_rows(rows):
    if not isinstance(rows, list) or len(rows) > 16:
        raise Invalid("At most 16 near register pointer relations")
    used = set()
    for p in rows:
        fields(p, {"register", "segment", "region"}, {"register", "segment", "region"})
        if not all(isinstance(v, str) for v in p.values()):
            raise Invalid("Pointer fields must be strings")
        if p["register"] not in "ax bx cx dx si di bp".split() or p["segment"] not in (
            "ds",
            "es",
        ):
            raise Unsupported(
                "Only general 16 bit register pointers through DS/ES are qualified"
            )
        if p["register"] in used:
            raise Invalid("Duplicate pointer register")
        used.add(p["register"])
    return rows


def load_comparison(path):
    source = Path(path).resolve()
    raw = source.read_bytes()
    return comparison_contract(json.loads(raw)), {
        "path": str(source),
        "sha256": digest(raw),
    }


def validate_observations(analysis, rows, side):
    for row in rows:
        address, size = row[side], row["size"]
        maximum = 0x110000 if analysis.real else 1 << 47
        if address + size > maximum:
            raise Unsupported(
                "Final RAM observation outside the qualified address range"
            )
        if any(
            address < a + len(raw) and a < address + size for a, raw in analysis.chunks
        ):
            raise Unsupported("Final RAM observations cannot include selected code")


def final_bytes(analysis, state, rows, side):
    values = []
    for row in rows:
        address, size = row[side], row["size"]
        if not set(range(address, address + size)) <= state.globals["initialized"]:
            raise Unsupported("Final RAM observation includes uninitialized bytes")
        values.append(
            state.memory.load(address, size, inspect=False, disable_actions=True)
        )
    return values


def materialize_memory(analysis, state, rows, side):
    return [
        {
            "name": r["name"],
            "address": r[side],
            "hex": state.solver.eval(v).to_bytes(r["size"], "big").hex(),
        }
        for r, v in zip(rows, final_bytes(analysis, state, rows, side))
    ]


def omitted_writes(analysis, rows, side):
    observed = {a for r in rows for a in range(r[side], r[side] + r["size"])}
    sites = set()
    for state in analysis.leaves:
        for _, kind, ins, expr, size, _ in state.globals["events"]:
            if kind != "write":
                continue
            addresses = state.solver.eval_upto(
                expr, analysis.spec["limits"]["addresses"] + 1
            )
            for address in addresses:
                if not set(range(address, address + size)) <= observed:
                    sites.add((ins, address, size))
    return {
        "distinct_sites": len(sites),
        "truncated": len(sites) > 64,
        "sites": [
            {"instruction": i, "address": a, "size": s}
            for i, a, s in sorted(sites)[:64]
        ],
        "scope": "Completed paths only; bytes outside selected final regions are unproved",
    }
