"""Private child entry point for the portable CLI deadline."""

import argparse
import json
import sys

from .cli import result_for


def main():
    args = argparse.Namespace(**json.loads(sys.stdin.buffer.read()))
    result = result_for(args, bounded=True)
    sys.stdout.buffer.write(json.dumps(result).encode("utf-8") + b"\n")


if __name__ == "__main__":
    main()
