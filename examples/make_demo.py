"""Write runnable examples into a new directory.

Usage: python examples/make_demo.py bitfield demo
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def bitfield_files():
    # Each row pairs machine bytes with the instruction they encode.
    word = [
        ("a10001", "mov ax, word ptr [0x100]"),
        ("c1e804", "shr ax, 4"),
        ("83e007", "and ax, 7"),
    ]
    byte = [
        ("31c0", "xor ax, ax"),
        ("a00001", "mov al, byte ptr [0x100]"),
        ("c1e804", "shr ax, 4"),
        ("83e007", "and ax, 7"),
    ]
    wrong = word[:-1] + [("83e003", "and ax, 3")]
    files = {}
    for name, instructions in (("word", word), ("byte", byte), ("wrong", wrong)):
        code = bytes.fromhex("".join(raw for raw, _ in instructions))
        contract = {
            "schema": 1,
            "architecture": "x86:LE:16:Real Mode",
            "entry": "0x11000",
            "code": [{"address": "0x11000", "size": len(code)}],
            "stops": [{"address": 0x11000 + len(code), "kind": "boundary"}],
            "registers": {
                "cs": "0x1000",
                "ds": "0x4000",
                "ss": "0x7000",
                "es": "0xa000",
                "sp": "0x8000",
            },
            "flags": "0x202",
            "memory": [{"address": "0x40100", "symbolic": True, "size": 2}],
            "claims": [{"kind": "preserved", "register": "bx"}],
        }
        files[name + ".bin"] = code
        files[name + ".json"] = (json.dumps(contract, indent=2) + "\n").encode()
        listing = "; 16-bit x86, DS = 0x4000\n" + "\n".join(
            instruction for _, instruction in instructions
        )
        files[name + ".asm"] = (listing + "\n").encode()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("bitfield", "final-memory", "layout"))
    parser.add_argument("directory", type=Path, help="A new output directory")
    args = parser.parse_args()
    if args.directory.exists():
        parser.error("Output directory already exists; choose a new name.")
    if args.kind == "bitfield":
        files = bitfield_files()
    else:
        # Use the installed command's public interface to get the paired examples.
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "binquery",
                "example",
                "--kind",
                args.kind,
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        bundle = json.loads(done.stdout)
        files = {
            name: bytes.fromhex(row["hex"])
            if "hex" in row
            else (json.dumps(row["json"], indent=2) + "\n").encode()
            for name, row in bundle["files"].items()
        }
    args.directory.mkdir(parents=True)
    for name, content in files.items():
        (args.directory / name).write_bytes(content)
    print(f"Created {args.directory}. See docs/CAPABILITIES.md for the commands.")


if __name__ == "__main__":
    main()
