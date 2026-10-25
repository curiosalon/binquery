"""Create a small program that writes a result and then reads it back."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.directory.exists():
        parser.error("Choose a new directory; the destination already exists")
    example = json.loads(
        subprocess.check_output(
            [
                sys.executable,
                "-m",
                "binquery",
                "example",
                "--kind",
                "analysis",
                "--arch",
                "real16",
                "--json",
            ],
            text=True,
            encoding="utf-8",
        )
    )
    # Append MOV BX,[0200] to the generated branch-and-store program.
    raw = bytes.fromhex(example["binary_hex"] + "8b1e0002")
    contract = example["contract"]
    contract["code"][0]["size"] = len(raw)
    contract["stops"][0]["address"] = 0x11000 + len(raw)
    args.directory.mkdir(parents=True)
    (args.directory / "routine.bin").write_bytes(raw)
    (args.directory / "analysis.json").write_text(
        json.dumps(contract, indent=2) + "\n", encoding="utf-8"
    )
    print(args.directory)


if __name__ == "__main__":
    main()
