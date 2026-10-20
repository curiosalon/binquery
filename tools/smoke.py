"""Exercise the installed package with synthetic inputs on any host OS."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="binquery-smoke-") as work:
        root = Path(work)

        def cli(*args, expected=0):
            done = subprocess.run(
                [sys.executable, "-m", "binquery", *args, "--json"],
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=90,
            )
            if done.returncode != expected:
                raise RuntimeError(
                    f"{args}: exit {done.returncode}\n{done.stdout}\n{done.stderr}"
                )
            return json.loads(done.stdout)

        cli("schema")
        cli("schema", "--kind", "comparison")
        for kind in ("final-memory", "layout"):
            bundle = cli("example", "--kind", kind)
            for name, row in bundle["files"].items():
                (root / name).write_bytes(
                    bytes.fromhex(row["hex"])
                    if "hex" in row
                    else json.dumps(row["json"]).encode("utf-8")
                )
            args = (
                "compare",
                "left.bin",
                "right.bin",
                "--contract",
                "left.json",
                "--right-contract",
                "right.json",
                "--comparison",
                "comparison.json",
            )
            assert cli(*args)["status"] == "EQUIVALENT_WITHIN_MODEL"
            result = cli(*args, "--effects", expected=1)
            assert (
                result["comparisons"]["final_memory"]["status"]
                == "EQUIVALENT_WITHIN_MODEL"
            )
            assert (
                result["comparisons"]["ordered_memory_effects"]["status"] == "DIFFERENT"
            )
            (root / "difference.json").write_text(json.dumps(result), encoding="utf-8")
            for side in ("left", "right"):
                assert cli(
                    "replay",
                    side + ".bin",
                    "--contract",
                    side + ".json",
                    "--witness",
                    "difference.json",
                    "--side",
                    side,
                    "--aspect",
                    "ordered_memory_effects",
                )["matched"]
        print(
            "Installed CLI: schemas, final RAM, layout, differences and both replays passed."
        )


if __name__ == "__main__":
    main()
