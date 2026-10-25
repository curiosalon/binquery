"""Analysis contract: explicit mappings and separate entry states, using v1 types."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from .model import Invalid, Unsupported, digest, fields, number, validate

EXTRA_LIMITS = {"events": 100000, "checkpoint_mb": 128, "variants": 32, "replays": 16}
EXTRA_MAX = {"events": 1000000, "checkpoint_mb": 1024, "variants": 256, "replays": 256}


def load(binary, path):
    source = Path(path).resolve()
    raw = source.read_bytes()
    d = json.loads(raw)
    fields(
        d,
        {
            "schema",
            "architecture",
            "code",
            "memory",
            "entries",
            "stops",
            "limits",
            "a20",
            "shift_count",
            "ports",
            "interrupts",
        },
        {"schema", "architecture", "code", "entries"},
    )
    if d["schema"] != 2:
        raise Invalid("analyze requires analysis contract schema 2")
    if not isinstance(d["entries"], list) or not 1 <= len(d["entries"]) <= 128:
        raise Invalid("entries must contain 1..128 separate starting states")
    binary = Path(binary).resolve()
    identities = {str(binary): digest(binary.read_bytes()), str(source): digest(raw)}
    limits = d.get("limits", {})
    fields(
        limits,
        {"steps", "states", "seconds", "solver_ms", "addresses"} | EXTRA_LIMITS.keys(),
    )
    extra = {k: number(limits.get(k, v)) for k, v in EXTRA_LIMITS.items()}
    if any(not 0 < v <= EXTRA_MAX[k] for k, v in extra.items()):
        raise Invalid("Analysis limits outside documented caps")
    for key in ("code", "memory", "ports", "interrupts", "stops"):
        if not isinstance(d.get(key, []), list):
            raise Invalid(f"{key} must be a list")
    entries, names = [], set()
    for entry in d["entries"]:
        fields(
            entry,
            {
                "name",
                "address",
                "registers",
                "flags",
                "memory",
                "program",
                "space",
                "load_context",
            },
            {
                "name",
                "address",
                "registers",
                "flags",
                "program",
                "space",
                "load_context",
            },
        )
        if not all(
            isinstance(entry[k], str) and entry[k]
            for k in ("name", "program", "space", "load_context")
        ):
            raise Invalid("Entry identity strings must be nonempty")
        if entry["name"] in names:
            raise Invalid("Duplicate entry name")
        names.add(entry["name"])
        if not isinstance(entry.get("memory", []), list):
            raise Invalid("Entry memory must be a list")
        code, memory, mappings = [], [], []
        for kind, rows in (
            ("code", d["code"]),
            ("memory", d.get("memory", []) + entry.get("memory", [])),
        ):
            if not isinstance(rows, list):
                raise Invalid("Mappings must be lists")
            for original in rows:
                row = copy.deepcopy(original)
                fields(
                    row,
                    {
                        "name",
                        "file",
                        "offset",
                        "address",
                        "size",
                        "sha256",
                        "segment",
                        "permissions",
                        "hex",
                        "symbolic",
                        "min",
                        "max",
                    },
                    {"address"},
                )
                permissions = row.pop("permissions", "rx" if kind == "code" else "rw")
                name = row.pop("name", kind)
                if (
                    not isinstance(permissions, str)
                    or not permissions
                    or set(permissions) - set("rwx")
                    or len(set(permissions)) != len(permissions)
                ):
                    raise Invalid("permissions uses each of r,w,x at most once")
                if (
                    kind == "code"
                    and "x" not in permissions
                    or kind == "memory"
                    and "x" in permissions
                ):
                    raise Invalid(
                        "Executable mappings belong in code; nonexecutable mappings in memory"
                    )
                mapping = dict(row, name=name, permissions=permissions, kind=kind)
                if "file" in row or kind == "code":
                    file = (
                        (source.parent / row["file"]).resolve()
                        if "file" in row
                        else binary
                    )
                    data = file.read_bytes()
                    identities[str(file)] = digest(data)
                    offset, size = (
                        number(row.get("offset", 0)),
                        number(row.get("size", 0)),
                    )
                    if offset < 0 or size <= 0 or offset + size > len(data):
                        raise Invalid("Mapping exceeds its input file")
                    if row.get("sha256", digest(data)) != digest(data):
                        raise Invalid("Mapping file identity differs")
                    mapping.update(
                        file=str(file), offset=offset, size=size, sha256=digest(data)
                    )
                    if kind == "memory":
                        if set(row) - {"file", "address", "offset", "size", "sha256"}:
                            raise Invalid(
                                "File-backed data cannot also declare initial values"
                            )
                        row = {
                            "address": row["address"],
                            "hex": data[offset : offset + size].hex(),
                        }
                    else:
                        row["file"] = str(file)
                size = (
                    number(row["size"])
                    if "size" in row
                    else (
                        1
                        if row.get("symbolic")
                        else len(bytes.fromhex(row.get("hex", "")))
                    )
                )
                mapping.update(address=number(row["address"]), size=size)
                mappings.append(mapping)
                (code if kind == "code" else memory).append(row)
        spec = {
            "schema": 1,
            "architecture": d["architecture"],
            "entry": entry["address"],
            "code": code,
            "memory": memory,
            "stops": copy.deepcopy(d.get("stops", [])),
            "registers": copy.deepcopy(entry["registers"]),
            "flags": entry["flags"],
            "limits": {k: v for k, v in limits.items() if k not in EXTRA_LIMITS},
            "a20": d.get("a20", True),
            "shift_count": d.get("shift_count", "portable"),
        }
        spec = validate(spec, source, analysis=True)
        if not any(
            r["address"] <= spec["entry"] < r["address"] + r["size"]
            for r in spec["code"]
        ):
            raise Invalid("Entry must be in an executable mapping")
        entries.append(
            {
                "identity": {
                    k: entry[k] for k in ("name", "program", "space", "load_context")
                },
                "spec": spec,
                "mappings": mappings,
            }
        )
    ports = copy.deepcopy(d.get("ports", []))
    seen = set()
    for port in ports:
        fields(port, {"port", "width", "reads", "domain", "write"}, {"port", "width"})
        port["port"], port["width"] = number(port["port"]), number(port["width"])
        key = port["port"], port["width"]
        if key in seen or not 0 <= key[0] <= 65535 or key[1] not in (1, 2):
            raise Invalid("Duplicate or invalid port/width")
        seen.add(key)
        if "reads" in port and "domain" in port:
            raise Invalid("Use a finite read sequence OR a read domain")
        for field in ("reads", "domain"):
            if field in port:
                if (
                    not isinstance(port[field], list)
                    or not 1 <= len(port[field]) <= 256
                ):
                    raise Invalid("Port responses require 1..256 values")
                port[field] = [number(v) for v in port[field]]
                if any(not 0 <= v < 1 << (8 * key[1]) for v in port[field]):
                    raise Invalid("Port value exceeds width")
        if type(port.get("write", False)) is not bool:
            raise Invalid("Port write must be boolean")
    interrupts = [number(n) for n in d.get("interrupts", [])]
    if len(set(interrupts)) != len(interrupts) or any(
        not 0 <= n <= 255 for n in interrupts
    ):
        raise Invalid("interrupts lists distinct supplied IVT vectors 0..255")
    if (ports or interrupts) and d["architecture"] != "x86:LE:16:Real Mode":
        raise Unsupported(
            "Native device and interrupt adapter currently requires real16"
        )
    return {
        "entries": entries,
        "ports": ports,
        "interrupts": interrupts,
        "limits": entries[0]["spec"]["limits"] | extra,
        "inputs": identities,
        "binary": str(binary),
        "contract": str(source),
    }
