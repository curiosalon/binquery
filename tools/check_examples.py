"""Run the documented examples against the installed binquery command."""

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, work, expected=0):
    done = subprocess.run(
        [str(arg) for arg in args],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    if done.returncode != expected:
        raise RuntimeError(
            f"{args}: exit {done.returncode}, expected {expected}\n"
            f"{done.stdout}\n{done.stderr}"
        )
    return done


def cli(work, *args, expected=0):
    done = run([sys.executable, "-m", "binquery", *args, "--json"], work, expected)
    return json.loads(done.stdout)


def compare(work, directory, left, right, *extra, expected=0):
    return cli(
        work,
        "compare",
        f"{directory}/{left}.bin",
        f"{directory}/{right}.bin",
        "--contract",
        f"{directory}/{left}.json",
        "--right-contract",
        f"{directory}/{right}.json",
        *extra,
        expected=expected,
    )


def snippets(document, work):
    # Execute the actual Python blocks readers copy from the documentation.
    text = (ROOT / "docs" / document).read_text(encoding="utf-8")
    for code in re.findall(r"```python\n(.*?)\n```", text, flags=re.DOTALL):
        run([sys.executable, "-c", code], work)


def main():
    with tempfile.TemporaryDirectory(prefix="binquery-examples-") as directory:
        work = Path(directory)
        shutil.copytree(ROOT / "examples", work / "examples")
        result = compare(work, "examples", "inc", "add", "--observe", "ax")
        assert result["status"] == "EQUIVALENT_WITHIN_MODEL"
        result = compare(
            work,
            "examples",
            "inc",
            "add",
            "--observe",
            "ax",
            "--observe",
            "cf",
            expected=1,
        )
        assert result["witness"]["left"]["registers"]["ax"] == 0xFFFF

        for kind, output in (
            ("bitfield", "demo"),
            ("final-memory", "demo-memory"),
            ("layout", "demo-layout"),
        ):
            run([sys.executable, "examples/make_demo.py", kind, output], work)
        # A repeated invocation must leave the existing example untouched.
        before = (work / "demo/word.bin").read_bytes()
        run([sys.executable, "examples/make_demo.py", "bitfield", "demo"], work, 2)
        assert (work / "demo/word.bin").read_bytes() == before
        view = cli(
            work,
            "inspect",
            "demo/word.bin",
            "--format",
            "blob",
            "--arch",
            "x86:LE:16:Real Mode",
            "--base",
            "0x11000",
        )
        assert view["decoded_bytes"] == 9
        query = cli(work, "query", "demo/word.bin", "--contract", "demo/word.json")
        assert query["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"
        assert (
            compare(work, "demo", "word", "byte", "--observe", "ax")["status"]
            == "EQUIVALENT_WITHIN_MODEL"
        )
        wrong = compare(work, "demo", "word", "wrong", "--observe", "ax", expected=1)
        assert (
            wrong["replay"]["left"]["registers"]["ax"]
            != wrong["replay"]["right"]["registers"]["ax"]
        )
        (work / "demo/wrong-result.json").write_text(
            json.dumps(wrong), encoding="utf-8"
        )
        for side, binary in (("left", "word"), ("right", "wrong")):
            assert cli(
                work,
                "replay",
                f"demo/{binary}.bin",
                "--contract",
                f"demo/{binary}.json",
                "--witness",
                "demo/wrong-result.json",
                "--side",
                side,
                "--aspect",
                "registers",
            )["matched"]
        reads = compare(
            work,
            "demo",
            "word",
            "byte",
            "--observe",
            "ax",
            "--effects",
            expected=1,
        )
        assert reads["comparisons"]["registers"]["status"] == "EQUIVALENT_WITHIN_MODEL"
        assert [e["size"] for e in reads["replay"]["left"]["events"]] == [2]
        assert [e["size"] for e in reads["replay"]["right"]["events"]] == [1]
        (work / "demo/reads.json").write_text(json.dumps(reads), encoding="utf-8")
        for folder in ("demo-memory", "demo-layout"):
            options = ("--comparison", f"{folder}/comparison.json")
            assert (
                compare(work, folder, "left", "right", *options)["status"]
                == "EQUIVALENT_WITHIN_MODEL"
            )
            different = compare(
                work, folder, "left", "right", *options, "--effects", expected=1
            )
            assert (
                different["comparisons"]["final_memory"]["status"]
                == "EQUIVALENT_WITHIN_MODEL"
            )
        compare(
            work,
            "demo-layout",
            "left",
            "right",
            "--comparison",
            "demo-layout/comparison.json",
            "--observe",
            "ax",
            expected=1,
        )
        snippets("CAPABILITIES.md", work)
        # Windows PowerShell 5.1 redirects stdout as UTF-16.
        for name in ("wrong-result.json", "reads.json"):
            saved = work / "demo" / name
            saved.write_bytes(saved.read_text(encoding="utf-8").encode("utf-16"))
        snippets("CAPABILITIES.md", work)
        print(
            "Passed: add-one, packed bits, wrong mask, replays, RAM, layout, tutorial snippets."
        )

        run([sys.executable, "examples/saved_analysis.py", "trace-demo"], work)
        checkpoint = "trace-demo/run.bq"
        initial = cli(
            work,
            "analyze",
            "trace-demo/routine.bin",
            "--contract",
            "trace-demo/analysis.json",
            "--save",
            checkpoint,
            "--steps",
            "2",
            expected=2,
        )
        assert initial["metrics"]["pending_paths"]
        resumed = cli(work, "analyze", "--resume", checkpoint, "--steps", "128")
        assert resumed["complete"] and len(resumed["paths"]) == 2
        assert all(path["replay"]["matched"] for path in resumed["paths"])
        assert cli(work, "report", checkpoint, "--check-inputs")["complete"]
        before = (work / checkpoint).read_bytes()
        cli(work, "analyze", "--resume", checkpoint, "--steps", "128")
        assert (work / checkpoint).read_bytes() == before
        write = cli(
            work,
            "query",
            "--analysis",
            checkpoint,
            "--kind",
            "access",
            "--access",
            "write",
            "--range",
            "0x40200:2",
            "--expect",
            "always",
        )
        assert write["status"] == "ESTABLISHED"
        suppliers = cli(
            work,
            "query",
            "--analysis",
            checkpoint,
            "--kind",
            "last-write",
            "--site",
            "0x1100f",
        )
        assert suppliers["status"] == "ESTABLISHED"
        for match in suppliers["matches"]:
            for byte in match["bytes"]:
                assert all(row["instruction"] == 0x1100C for row in byte["writers"])
        dot = run(
            [
                sys.executable,
                "-m",
                "binquery",
                "graph",
                checkpoint,
                "--view",
                "memory",
                "--format",
                "dot",
            ],
            work,
        )
        assert "digraph" in dot.stdout
        snippets("EXECUTION.md", work)
        print(
            "Passed: saved analysis, resume, memory suppliers, graph, scripting example."
        )

        compiler = shutil.which("clang")
        if compiler is None:
            print("Skipped compiled C/C++ examples: clang is not on PATH.")
            return
        for source, output in (
            ("scalar.c", "scalar.o"),
            ("scalar.cpp", "scalar-cpp.o"),
            ("different.c", "different.o"),
        ):
            run(
                [
                    compiler,
                    "--target=x86_64-unknown-linux-gnu",
                    "-O2",
                    "-ffreestanding",
                    "-c",
                    f"examples/{source}",
                    "-o",
                    output,
                ],
                work,
            )
        for right, output, code, status in (
            ("scalar-cpp.o", "demo-compiled", 0, "EQUIVALENT_WITHIN_MODEL"),
            ("different.o", "demo-different", 1, "DIFFERENT"),
        ):
            run(
                [
                    sys.executable,
                    "examples/compare_functions.py",
                    "scalar.o",
                    right,
                    "--output",
                    output,
                ],
                work,
                code,
            )
            result = json.loads(
                (work / output / "result.json").read_text(encoding="utf-8")
            )
            assert result["status"] == status
        cli(
            work,
            "compare",
            "scalar.o",
            "scalar-cpp.o",
            "--contract",
            "demo-compiled/left.json",
            "--right-contract",
            "demo-compiled/right.json",
            "--observe",
            "rax",
        )
        missing = run(
            [
                sys.executable,
                "examples/compare_functions.py",
                "scalar.o",
                "scalar-cpp.o",
                "--symbol",
                "missing_symbol",
                "--output",
                "missing-result",
            ],
            work,
            2,
        )
        assert "Selected function symbol not found" in missing.stderr
        assert not (work / "missing-result").exists()
        snippets("COMPILED.md", work)
        print("Passed: compiled C/C++ equality, changed function, scripting example.")


if __name__ == "__main__":
    main()
