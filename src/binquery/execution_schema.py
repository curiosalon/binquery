"""Published schema and runnable examples for the analysis interface."""

import copy

from .discovery import contract_schema, example
from .execution_contract import EXTRA_LIMITS, EXTRA_MAX


def schema():
    old = contract_schema()["properties"]
    integer = old["entry"]
    extra = {
        "name": {"type": "string"},
        "permissions": {"type": "string", "pattern": "^[rwx]{1,3}$"},
    }
    code = copy.deepcopy(old["code"])
    code["items"]["properties"].update(extra)
    memory = copy.deepcopy(old["memory"])
    for form in memory["items"]["oneOf"]:
        form["properties"].update(extra)
    filedata = copy.deepcopy(code["items"])
    filedata["required"] = ["file", "address", "size"]
    del filedata["properties"]["segment"]
    memory["items"]["oneOf"].append(filedata)
    entry = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            **{
                k: {"type": "string", "minLength": 1}
                for k in ("name", "program", "space", "load_context")
            },
            "address": integer,
            "registers": old["registers"],
            "flags": old["flags"],
            "memory": memory,
        },
        "required": [
            "name",
            "program",
            "space",
            "load_context",
            "address",
            "registers",
            "flags",
        ],
    }
    limits = copy.deepcopy(old["limits"])
    limits["properties"]["steps"]["maximum"] = 1048576
    limits["properties"]["steps"]["description"] = (
        "Cumulative per-path instruction ceiling; maximum 1048576"
    )
    limits["properties"].update(
        {
            k: dict(integer, default=v, description=f"Positive, maximum {EXTRA_MAX[k]}")
            for k, v in EXTRA_LIMITS.items()
        }
    )
    stops = copy.deepcopy(old["stops"])
    stops["minItems"] = 0
    ports = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["port", "width"],
            "properties": {
                "port": integer,
                "width": integer,
                "write": {"type": "boolean"},
                "reads": {
                    "type": "array",
                    "items": integer,
                    "minItems": 1,
                    "maxItems": 256,
                },
                "domain": {
                    "type": "array",
                    "items": integer,
                    "minItems": 1,
                    "maxItems": 256,
                },
            },
            "not": {"required": ["reads", "domain"]},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Binquery execution analysis, schema 2",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "architecture", "code", "entries"],
        "properties": {
            "schema": {"const": 2},
            "architecture": old["architecture"],
            "code": code,
            "memory": memory,
            "entries": {
                "type": "array",
                "items": entry,
                "minItems": 1,
                "maxItems": 128,
            },
            "stops": stops,
            "limits": limits,
            "a20": old["a20"],
            "shift_count": old["shift_count"],
            "ports": ports,
            "interrupts": {"type": "array", "items": integer, "uniqueItems": True},
        },
        "description": "Mappings and separate starting states. Runtime checks enforce bounds, identities and supported semantics.",
    }


def discover(args):
    if args.command == "schema":
        return {
            "operation": "schema",
            "status": "DESCRIBED",
            "contract_schema": schema(),
        }
    old = example(args.arch)
    real = args.arch == "real16"
    raw = "83f805730583c003eb0231c0a30002" if real else "4883c001"
    old["code"][0]["size"] = len(bytes.fromhex(raw))
    old["stops"][0]["address"] = old["entry"] + len(bytes.fromhex(raw))
    old["registers"]["ax" if real else "rax"] = {"symbolic": True}
    contract = {
        "schema": 2,
        "architecture": old["architecture"],
        "code": old["code"],
        "stops": old["stops"],
        "memory": [{"address": 0x40200, "hex": "0000"}] if real else [],
        "entries": [
            {
                "name": "main",
                "program": "example",
                "space": "ram",
                "load_context": "initial",
                "address": old["entry"],
                "registers": old["registers"],
                "flags": old["flags"],
            }
        ],
    }
    return {
        "operation": "example",
        "status": "DESCRIBED",
        "contract": contract,
        "binary_hex": raw,
        "commands": [
            "binquery analyze example.bin --contract example.json --save example.bq",
            "binquery report example.bq --json",
            "binquery graph example.bq --view flow --format dot",
        ],
    }
