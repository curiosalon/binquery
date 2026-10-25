"""Native contract discovery; no target inspection or guessed machine state."""

import copy

REAL16 = "x86:LE:16:Real Mode"


def contract_schema():
    integer = {
        "anyOf": [
            {"type": "integer"},
            {
                "type": "string",
                "pattern": r"^[+-]?(0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|0+|[1-9][0-9]*)$",
            },
        ],
        "description": "Integer or canonical decimal/0x/0o/0b string; bounds checked by binquery.",
    }

    def obj(properties, required=()):
        return {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
        }

    def array(items, **kwargs):
        return {"type": "array", "items": items, **kwargs}

    symbolic = obj(
        {"symbolic": {"const": True}, "min": integer, "max": integer}, ["symbolic"]
    )
    claims = []
    for kind, extra in [
        ("preserved", {"register": {"type": "string"}}),
        ("return_equals", {"register": {"type": "string"}, "value": integer}),
        ("no_read", {"instruction": integer}),
    ]:
        claims.append(
            obj(
                {"kind": {"const": kind}, "name": {"type": "string"}, **extra},
                ["kind", *extra],
            )
        )
    limits = {
        "steps": (128, 4096),
        "states": (256, 4096),
        "seconds": (30, 300),
        "solver_ms": (5000, 60000),
        "addresses": (32, 256),
    }
    code = obj(
        {
            "address": integer,
            "size": integer,
            "offset": integer,
            "segment": integer,
            "file": {
                "type": "string",
                "description": "Raw auxiliary input, relative to the contract file.",
            },
            "sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
                "description": "Whole input file hash, in blob and auto modes.",
            },
        },
        ["address", "size"],
    )
    memory = {
        "oneOf": [
            obj(
                {
                    "address": integer,
                    "hex": {"type": "string", "pattern": "^([0-9a-fA-F]{2})+$"},
                },
                ["address", "hex"],
            ),
            obj(
                {
                    "address": integer,
                    "symbolic": {"const": True},
                    "size": integer,
                    "min": integer,
                    "max": integer,
                },
                ["address", "symbolic"],
            ),
        ]
    }
    schema = obj(
        {
            "schema": {"const": 1},
            "format": {"enum": ["blob", "auto"], "default": "blob"},
            "architecture": {"enum": ["AMD64", REAL16]},
            "entry": integer,
            "code": array(code, minItems=1, maxItems=128),
            "stops": array(
                obj(
                    {
                        "address": integer,
                        "kind": {"enum": ["return", "failure", "boundary"]},
                    },
                    ["address", "kind"],
                ),
                minItems=1,
            ),
            "registers": {
                "type": "object",
                "propertyNames": {"pattern": "^[a-z][a-z0-9]*$"},
                "additionalProperties": {"oneOf": [integer, symbolic]},
                "description": "Unlisted general registers are symbolic. Real mode requires concrete CS, DS, SS, ES and SP.",
            },
            "flags": integer,
            "memory": array(memory),
            "claims": array({"oneOf": claims}),
            "limits": obj(
                {
                    k: dict(
                        integer,
                        default=default,
                        description=f"Positive, maximum {maximum}.",
                    )
                    for k, (default, maximum) in limits.items()
                }
            ),
            "a20": {"const": True, "default": True},
            "shift_count": {
                "enum": ["portable", "masked5"],
                "default": "portable",
                "description": "portable requires raw counts 0..31; masked5 explicitly selects 286-and-later five-bit count masking. No 8086 count-above-31 support.",
            },
        },
        ["schema", "entry", "code", "stops", "registers", "flags"],
    )
    schema.update(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "binquery machine contract, schema 1",
            "description": "Structural schema using canonical textual numbers and hex. Runtime validation additionally checks numeric limits, flags, registers, code identities/boundaries, overlaps, address ranges and instruction support. Schema validation alone is not qualification.",
            "allOf": [
                {
                    "if": {"properties": {"format": {"const": "blob"}}},
                    "then": {"required": ["architecture"]},
                }
            ],
        }
    )
    return schema


def example(profile):
    real = profile == "real16"
    address = 0x11000 if real else 0x400000
    model = {
        "schema": 1,
        "format": "blob",
        "architecture": REAL16 if real else "AMD64",
        "entry": address,
        "code": [{"address": address, "size": 1}],
        "stops": [{"address": address + 1, "kind": "boundary"}],
        "registers": {
            "cs": 0x1000,
            "ds": 0x4000,
            "ss": 0x7000,
            "es": 0xA000,
            "sp": 0x8000,
        }
        if real
        else {"rsp": 0x700000},
        "flags": 0x202,
        "memory": [],
        "claims": [{"kind": "preserved", "register": "ax" if real else "rax"}],
        "limits": {"steps": 8, "states": 8, "seconds": 10},
    }
    return copy.deepcopy(model)


def discover(args):
    if args.command == "schema":
        if args.kind == "comparison":
            return {
                "operation": "schema",
                "status": "DESCRIBED",
                "comparison_schema": comparison_schema(),
                "next": "binquery example --kind layout --json",
            }
        return {
            "operation": "schema",
            "status": "DESCRIBED",
            "contract_schema": contract_schema(),
            "next": "binquery example --arch real16 --contract-only > model.json",
        }
    if args.kind != "machine":
        from .model import Unsupported

        if args.contract_only or args.arch != "real16":
            raise Unsupported(
                "Paired examples emit a real16 JSON file bundle; omit --contract-only and use --json"
            )
        return paired_example(args.kind)
    model = example(args.arch)
    return {
        "operation": "example",
        "status": "DESCRIBED",
        "contract": model,
        "binary_hex": "90",
        "description": "One NOP with explicit synthetic initial state and a boundary stop. Adapt the contract to your actual binary; no target state is inferred.",
        "commands": [
            f"binquery example --arch {args.arch} --contract-only > model.json",
            "printf '\\220' > nop.bin",
            "binquery query nop.bin --contract model.json --json",
        ],
    }


def comparison_schema():
    integer = contract_schema()["properties"]["entry"]

    def obj(properties, required):
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }

    region = obj(
        {
            "name": {"type": "string", "minLength": 1},
            "left": integer,
            "right": integer,
            "size": integer,
        },
        ["name", "left", "right", "size"],
    )
    pointer = obj(
        {
            "register": {"enum": "ax bx cx dx si di bp".split()},
            "segment": {"enum": ["ds", "es"]},
            "region": {"type": "string", "minLength": 1},
        },
        ["register", "segment", "region"],
    )
    rows = {
        "type": "array",
        "items": region,
        "maxItems": 64,
        "description": "Unique names, nonoverlapping ranges per side; at most 4096 bytes total. Runtime checked.",
    }
    pointers = {
        "type": "array",
        "items": pointer,
        "maxItems": 16,
        "description": "Unique registers; complete near pointer domain must stay inside the named region.",
    }
    result = obj(
        {
            "schema": {"const": 1},
            "memory": rows,
            "pointers": pointers,
            "relation": obj(
                {
                    "regions": rows,
                    "pointers": pointers,
                    "stack": obj(
                        {"address": integer, "size": integer}, ["address", "size"]
                    ),
                },
                ["regions"],
            ),
        },
        ["schema"],
    )
    result.update(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "binquery bounded comparison contract, schema 1",
            "description": "Final ordinary RAM observations and optional real16 input/layout correspondence. Relation regions match every complete initial RAM row, with identical value domains. Segments and stack placement are fixed; only declared near register pointers translate. Runtime validates coverage, aliases and pointer domains. Pointer observables require relation. Omitted state remains unproved.",
        }
    )
    return result


def paired_example(kind):
    left, right = example("real16"), example("real16")
    for model in (left, right):
        model["claims"] = []
    if kind == "final-memory":
        a, b = "c70600010102", "c606000101c606010102"
        left["memory"] = [{"address": 0x40100, "symbolic": True, "size": 2}]
        right["memory"] = copy.deepcopy(left["memory"])
        comparison = {
            "schema": 1,
            "memory": [
                {"name": "buffer", "left": 0x40100, "right": 0x40100, "size": 2}
            ],
        }
    else:
        a, b = "a12001a30001b80001", "a12002a30002b80002"
        regions = [
            {"name": "result", "left": 0x40100, "right": 0x40200, "size": 2},
            {"name": "input", "left": 0x40120, "right": 0x40220, "size": 2},
        ]
        for side, model in (("left", left), ("right", right)):
            model["memory"] = [
                {"address": r[side], "symbolic": True, "size": r["size"]}
                for r in regions
            ]
        comparison = {
            "schema": 1,
            "memory": [copy.deepcopy(regions[0])],
            "pointers": [{"register": "ax", "segment": "ds", "region": "result"}],
            "relation": {
                "regions": regions,
                "stack": {"address": 0x77F00, "size": 0x200},
            },
        }
    for model, code in ((left, a), (right, b)):
        model["code"][0]["size"] = len(bytes.fromhex(code))
        model["stops"][0]["address"] = model["entry"] + len(bytes.fromhex(code))
    return {
        "operation": "example",
        "status": "DESCRIBED",
        "kind": kind,
        "description": "Synthetic two-image ordinary RAM example. Save each files member as named; no target bindings are inferred.",
        "files": {
            "left.bin": {"hex": a},
            "right.bin": {"hex": b},
            "left.json": {"json": left},
            "right.json": {"json": right},
            "comparison.json": {"json": comparison},
        },
        "commands": [
            "binquery compare left.bin right.bin --contract left.json --right-contract right.json --comparison comparison.json --json",
            "binquery compare left.bin right.bin --contract left.json --right-contract right.json --comparison comparison.json --effects --json",
        ],
        "expected": ["EQUIVALENT_WITHIN_MODEL", "DIFFERENT (raw ordered accesses)"],
    }
