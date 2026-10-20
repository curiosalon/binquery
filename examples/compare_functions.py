"""Compare two simple AMD64 ELF functions that take one integer and return one.

The example uses the System V ABI: RDI is the argument and RAX is the result.
Usage: python examples/compare_functions.py a.o b.o --output demo-compiled
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def inspect(path, symbol):
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "inspect",
            str(path),
            "--symbol",
            symbol,
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    view = json.loads(done.stdout)
    if done.returncode:
        raise ValueError(view.get("reason", view["status"]))
    if view["architecture"] != "AMD64" or view["format"] != "ELF":
        raise ValueError("This example expects AMD64 ELF object files.")
    if view["relocations"]:
        raise ValueError("This example expects a function without code relocations.")
    return view


def make_contract(view):
    # Simulate a caller: RET reads this address from the top of the stack.
    stack = 0x800008
    return_address = 0x900000
    return {
        "schema": 1,
        "format": "auto",
        "architecture": "AMD64",
        "entry": view["address"],
        "code": [{"address": view["address"], "size": view["selected_size"]}],
        "stops": [{"address": return_address, "kind": "return"}],
        "registers": {"rsp": stack},
        "flags": "0x202",
        "memory": [
            {"address": stack, "hex": return_address.to_bytes(8, "little").hex()}
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--symbol", default="add_one")
    parser.add_argument(
        "--output", required=True, type=Path, help="New results directory"
    )
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output directory already exists; choose a new name.")
    try:
        contracts = [
            make_contract(inspect(path, args.symbol))
            for path in (args.left, args.right)
        ]
    except (OSError, ValueError) as error:
        parser.error(str(error))
    args.output.mkdir(parents=True)
    for side, contract in zip(("left", "right"), contracts):
        (args.output / (side + ".json")).write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8"
        )
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "compare",
            str(args.left),
            str(args.right),
            "--contract",
            str(args.output / "left.json"),
            "--right-contract",
            str(args.output / "right.json"),
            "--observe",
            "rax",
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    (args.output / "result.json").write_text(done.stdout, encoding="utf-8")
    if done.stderr:
        print(done.stderr, file=sys.stderr, end="")
    result = json.loads(done.stdout)
    print(result["status"])
    print(f"Contracts and full result: {args.output}")
    return done.returncode


if __name__ == "__main__":
    sys.exit(main())
