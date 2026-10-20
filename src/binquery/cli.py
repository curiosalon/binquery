"""Unix CLI: JSON on stdout, diagnostics on stderr, meaningful exit statuses."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .model import Incomplete, Invalid, Unsupported, contract, digest, number


def inspect_file(args):
    import cle
    import capstone
    import archinfo
    from .realmode import LANGUAGE

    path = Path(args.binary).resolve()
    raw = path.read_bytes()
    result = {
        "operation": "inspect",
        "status": "INSPECTED",
        "binary": str(path),
        "sha256": digest(raw),
        "size": len(raw),
    }
    if args.format == "blob":
        if not args.arch:
            raise Invalid("Raw bytes need --arch")
        address, offset = args.base, args.offset
        size = args.size if args.size is not None else len(raw) - offset
        if args.symbol:
            raise Invalid("Raw bytes have no symbols")
        if offset < 0 or size <= 0 or offset + size > len(raw):
            raise Invalid("Selected raw range is outside the file")
        data = raw[offset : offset + size]
        arch = args.arch
    else:
        loader = cle.Loader(str(path), auto_load_libs=False)
        obj = loader.main_object
        result.update(
            format=type(obj).__name__,
            architecture=obj.arch.name,
            entry=obj.entry,
            mapped_base=obj.mapped_base,
        )
        address, size = args.address, args.size
        if args.symbol:
            sym = obj.get_symbol(args.symbol)
            if sym is None or not sym.is_function:
                raise Invalid("Selected function symbol not found")
            address = sym.rebased_addr
            size = size if size is not None else sym.size
        if address is None:
            result["functions"] = [
                {"name": s.name, "address": s.rebased_addr, "size": s.size}
                for s in obj.symbols
                if s.is_function and not s.is_import
            ][:100]
            result["limits"] = [
                "Symbol metadata only; no function discovery or execution"
            ]
            return result
        if size is None or size <= 0:
            raise Invalid("Selected function has no reliable size; supply --size")
        try:
            data = loader.memory.load(address, size)
        except KeyError as exc:
            raise Invalid("Selected virtual address range is unmapped") from exc
        arch = obj.arch.name
        result["relocations"] = [
            {
                "address": r.rebased_addr,
                "symbol": r.symbol.name if r.symbol else None,
                "type": type(r).__name__,
            }
            for r in obj.relocs
            if address <= r.rebased_addr < address + size
        ]
    if arch not in (LANGUAGE, "AMD64", "X86"):
        raise Unsupported("Focused instruction view currently supports x86 16/32/64")
    mode = (
        capstone.CS_MODE_16
        if arch == LANGUAGE
        else capstone.CS_MODE_64
        if arch == "AMD64"
        else capstone.CS_MODE_32
    )
    decoded = list(capstone.Cs(capstone.CS_ARCH_X86, mode).disasm(data, address))
    result.update(
        architecture=arch,
        address=address,
        selected_size=size,
        decoded_bytes=sum(i.size for i in decoded),
        instructions=[
            {
                "address": i.address,
                "bytes": i.bytes.hex(),
                "instruction": i.mnemonic + " " + i.op_str,
            }
            for i in decoded
        ],
        limits=[
            "Explicit selected extent; no automatic proof of function boundaries",
            "Relocations shown as metadata, not normalized or accepted",
        ],
    )
    return result


def run(args, *, bounded=False):
    if args.command in ("schema", "example"):
        from .discovery import discover

        return discover(args)
    if args.command == "inspect":
        return inspect_file(args)
    spec, identity = contract(args.contract)
    seconds = spec["limits"]["seconds"]
    right_spec = None
    if args.command == "compare":
        right_spec, right_id = contract(args.right_contract or args.contract)
        seconds += right_spec["limits"]["seconds"]
    if not bounded:
        from .deadline import run_bounded

        return run_bounded(vars(args), seconds)
    from .engine import Analysis
    from .queries import query, compare
    from .replay import replay

    if args.command == "query":
        result = query(args.binary, spec)
    elif args.command == "compare":
        from .observations import load_comparison

        config, comparison_id = (
            load_comparison(args.comparison)
            if args.comparison
            else ({"schema": 1, "memory": []}, None)
        )
        config.setdefault("memory", [])
        for value in args.observe_memory:
            parts = value.split(":")
            if len(parts) != 2:
                raise Invalid("--observe-memory needs ADDRESS:SIZE")
            address, size = map(number, parts)
            config["memory"].append(
                {
                    "name": f"cli_{len(config['memory'])}",
                    "left": address,
                    "right": address,
                    "size": size,
                }
            )
        result = compare(
            args.binary,
            args.right,
            spec,
            right_spec,
            args.observe,
            args.effects,
            config,
        )
        result["right_contract"] = right_id
        result["comparison"] = config
        if comparison_id:
            result["comparison_contract"] = comparison_id
    else:
        if args.claim < 0:
            raise Invalid("Claim index must be nonnegative")
        if args.aspect and not args.side:
            raise Invalid("--aspect requires --side for a saved comparison")
        saved = json.loads(Path(args.witness).read_bytes())
        source = saved
        identity_key = "contract"
        if args.side:
            if saved.get("operation") != "compare":
                raise Invalid("--side requires a saved comparison")
            source = saved[args.side]
            identity_key = "right_contract" if args.side == "right" else "contract"
        elif saved.get("operation") == "compare":
            raise Invalid("Comparison witness replay requires --side left or right")
        if saved.get(identity_key, {}).get("sha256") != identity["sha256"]:
            raise Invalid("Witness contract identity mismatch")
        analysis = Analysis(args.binary, spec)
        if source.get("binary", {}).get("sha256") != analysis.identity["sha256"]:
            raise Invalid("Witness binary identity mismatch")
        if source.get("code_ranges") != analysis.summary()["code_ranges"]:
            raise Invalid("Witness code range identity mismatch")
        try:
            if args.side:
                item = saved["comparisons"][args.aspect] if args.aspect else saved
                witness = item["witness"][args.side]
            else:
                witness = saved["claims"][args.claim]["witness"]
        except (KeyError, IndexError) as exc:
            raise Invalid(
                "Selected query claim or comparison aspect has no witness"
            ) from exc
        result = replay(analysis, witness)
        result.update(
            operation="replay",
            status="REPLAYED" if result["matched"] else "INCONCLUSIVE",
        )
        if args.side:
            result.update(
                side=args.side,
                scope="One concrete execution only; this does not re-establish paired equivalence",
            )
    result["contract"] = identity
    return result


def parser():
    from .discovery import example

    contract_help = (
        "Contract help: binquery schema --json; binquery example --arch real16 --json\n\n"
        "Contract fields: schema, format, architecture, entry, code, stops, registers,\n"
        "flags, memory, claims, limits, a20, shift_count. Use explicit code ranges and stops.\n"
        'Registers are concrete integers or {"symbolic":true,"min":0,"max":3};\n'
        "unlisted general registers are symbolic. Memory rows contain address and hex,\n"
        "or address/symbolic/size and optional unsigned min/max. Claims: preserved,\n"
        "return_equals, no_read. Numeric bounds and machine support are runtime checks.\n"
        "Real16 shift_count: portable (default) requires raw counts 0..31; masked5\n"
        "selects 286-and-later count masking. Undefined flag dependencies reject.\n\n"
        "Compare final RAM: --observe-memory ADDRESS:SIZE (repeatable). For different\n"
        "addresses and near pointers use --comparison FILE; schema --kind comparison.\n"
        "Unobserved memory is unproved; --effects separately checks raw access order.\n\n"
        "Runnable real16 NOP example (synthetic state, not inferred from a target):\n"
        "  printf '\\220' > nop.bin\n"
        "Save this JSON as model.json:\n"
        + json.dumps(example("real16"), separators=(",", ":"))
        + "\n  binquery query nop.bin --contract model.json --json"
    )
    p = argparse.ArgumentParser(
        description="Bounded queries against caller supplied binaries. No target process is launched.",
        epilog="Discover contracts: binquery schema --json; binquery example --arch real16 --json",
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    schema = sub.add_parser("schema", help="Describe the machine-contract JSON Schema")
    schema.add_argument(
        "--json", action="store_true", help="Schema and tool metadata as JSON"
    )
    schema.add_argument(
        "--schema-only",
        action="store_true",
        help="Emit just the JSON Schema for a validator",
    )
    schema.add_argument("--kind", choices=("machine", "comparison"), default="machine")
    example = sub.add_parser(
        "example", help="Show a runnable synthetic binary and contract example"
    )
    example.add_argument("--arch", choices=("real16", "AMD64"), default="real16")
    example.add_argument(
        "--json",
        action="store_true",
        help="Example contract, binary hex and commands as JSON",
    )
    example.add_argument(
        "--contract-only",
        action="store_true",
        help="Emit just the input contract, ready for shell redirection",
    )
    example.add_argument(
        "--kind", choices=("machine", "final-memory", "layout"), default="machine"
    )
    for command in ("query", "compare", "replay", "inspect"):
        c = sub.add_parser(
            command,
            epilog=contract_help,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        c.add_argument("binary", help="Input executable, object or raw code file")
        c.add_argument(
            "--json", action="store_true", help="Stable JSON result on stdout"
        )
        if command != "inspect":
            c.add_argument(
                "--contract",
                required=True,
                help="Machine state, code ranges, exits and limits (JSON)",
            )
        if command == "compare":
            c.add_argument("right", help="Second binary")
            c.add_argument(
                "--right-contract",
                help="Optional separate code placement/extent contract",
            )
            c.add_argument(
                "--observe",
                action="append",
                default=[],
                help="Observable register; repeat as needed",
            )
            c.add_argument(
                "--effects",
                action="store_true",
                help="Also compare ordered memory reads and writes",
            )
            c.add_argument(
                "--observe-memory",
                action="append",
                default=[],
                metavar="ADDRESS:SIZE",
                help="Compare these final RAM bytes on both sides; repeat as needed",
            )
            c.add_argument(
                "--comparison",
                help="Bounded final RAM, near pointer observables and optional input relation (JSON)",
            )
        elif command == "replay":
            c.add_argument(
                "--witness", required=True, help="Saved JSON query or comparison result"
            )
            c.add_argument(
                "--claim", type=int, default=0, help="Zero based claim with a witness"
            )
            c.add_argument(
                "--side",
                choices=("left", "right"),
                help="Replay one side of a saved comparison",
            )
            c.add_argument(
                "--aspect",
                choices=(
                    "registers",
                    "pointers",
                    "final_memory",
                    "ordered_memory_effects",
                    "exit_kind",
                ),
                help="Choose a comparison aspect's witness",
            )
        elif command == "inspect":
            c.add_argument("--format", choices=("auto", "blob"), default="auto")
            c.add_argument(
                "--arch", help="For raw bytes: AMD64, X86 or x86:LE:16:Real Mode"
            )
            c.add_argument("--base", type=number, default=0, help="Raw load address")
            c.add_argument("--offset", type=number, default=0, help="Raw file offset")
            c.add_argument("--address", type=number, help="Loaded virtual address")
            c.add_argument("--size", type=number, help="Explicit byte extent")
            c.add_argument("--symbol", help="Function symbol in executable/object")
    return p


def result_for(args, *, bounded=False):
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    try:
        result = run(args, bounded=bounded)
    except (Invalid, ValueError, OSError, KeyError) as exc:
        result = {"status": "INVALID", "reason": str(exc)}
    except (Unsupported, Incomplete) as exc:
        result = {
            "status": "UNSUPPORTED" if isinstance(exc, Unsupported) else "INCONCLUSIVE",
            "reason": str(exc),
        }
    except Exception as exc:
        result = {"status": "ERROR", "reason": type(exc).__name__ + ": " + str(exc)}
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    result = result_for(args)
    result["schema"] = 1
    result["tool"] = {
        "name": "binquery",
        "version": __version__,
        "angr": importlib.metadata.version("angr"),
        "pypcode": importlib.metadata.version("pypcode"),
        "unicorn": importlib.metadata.version("unicorn"),
    }
    statuses = [r["status"] for r in result.get("claims", [])] or [
        result.get("status", "INCONCLUSIVE")
    ]
    if (
        args.command == "schema"
        and args.schema_only
        and ("contract_schema" in result or "comparison_schema" in result)
    ):
        print(
            json.dumps(
                result.get("contract_schema", result.get("comparison_schema")), indent=2
            )
        )
    elif args.command == "example" and args.contract_only and "contract" in result:
        print(json.dumps(result["contract"], indent=2))
    elif args.json:
        print(json.dumps(result, indent=2))
    else:
        print(" / ".join(statuses))
        if "reason" in result:
            print(result["reason"])
        if result.get("operation") == "compare":
            print(result["scope"])
            for kind, item in result["comparisons"].items():
                print(f"{kind}: {item['status']}")
            for row in result["observables"]["final_memory"]:
                print(
                    f"Final RAM {row['name']}: left {row['left']:#x}, right {row['right']:#x}, {row['size']} bytes"
                )
            for side, omitted in result["writes_outside_final_memory"].items():
                print(
                    f"{side}: {omitted['distinct_sites']} completed-path write sites outside selected final RAM; omitted state is unproved"
                )
        for row in result.get("claims", []):
            print(f"{row['status']}: {row['claim'].get('name', row['claim']['kind'])}")
        if "instructions" in result:
            for row in result["instructions"]:
                print(f"{row['address']:08x}  {row['bytes']:<24} {row['instruction']}")
        elif args.command in ("inspect", "schema", "example"):
            print(json.dumps(result, indent=2))
        if "terminal_paths" in result:
            print(
                f"{result['terminal_paths']} terminal paths; complete={result['complete']}; {result['elapsed_seconds']:.3f}s"
            )
        if result.get("issues"):
            print(json.dumps(result["issues"]))
    if "ERROR" in statuses:
        return 4
    if "INVALID" in statuses:
        return 3
    if any(s in ("UNSUPPORTED", "INCONCLUSIVE") for s in statuses):
        return 2
    return 1 if any(s in ("REFUTED", "DIFFERENT") for s in statuses) else 0
