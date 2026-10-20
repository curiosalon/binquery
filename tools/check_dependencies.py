"""Check dependencies, disclosing one verified upstream macOS wheel-tag defect."""

import importlib.metadata
import platform
import subprocess
import sys


def known_z3_tag_warning(done):
    if (
        sys.platform != "darwin"
        or done.returncode != 1
        or done.stderr.strip()
        or done.stdout.strip() != "z3-solver 5.1.0.0 is not supported on this platform"
    ):
        return False
    release = tuple(int(x) for x in platform.mac_ver()[0].split("."))
    if release < (13, 3):
        return False
    dist = importlib.metadata.distribution("z3-solver")
    wheel = dist.read_text("WHEEL") or ""
    tags = [line for line in wheel.splitlines() if line.startswith("Tag:")]
    machine = platform.machine()
    return (
        dist.version == "5.1.0.0"
        and machine in ("arm64", "x86_64")
        and tags == [f"Tag: py3-none-macosx_13_3_{machine}"]
    )


def main():
    done = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    print(done.stdout, end="")
    print(done.stderr, end="", file=sys.stderr)
    if known_z3_tag_warning(done):
        print(
            "KNOWN UPSTREAM METADATA WARNING: Z3 5.1.0.0 macOS wheel has "
            "an internal 13_3 tag versus the published 13_0 filename. "
            "Runtime tests and smoke checks are still required."
        )
        return 0
    return done.returncode


if __name__ == "__main__":
    raise SystemExit(main())
