#!/usr/bin/env python3
"""Keep local binquery problem reports without running or submitting anything."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PureWindowsPath
import tempfile
import uuid


def now():
    return datetime.now(timezone.utc).isoformat()


def directory(value):
    if value:
        return Path(value).expanduser()
    if os.environ.get("BINQUERY_REPORT_DIR"):
        return Path(os.environ["BINQUERY_REPORT_DIR"]).expanduser()
    return (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        / "binquery/reports"
    )


def validate(request):
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    for key in ("title", "binquery_version", "expected", "actual", "cwd"):
        if not isinstance(request.get(key), str) or not request[key].strip():
            raise ValueError(f"{key} must be a nonempty string")
    if not (
        Path(request["cwd"]).is_absolute()
        or PureWindowsPath(request["cwd"]).is_absolute()
    ):
        raise ValueError(
            "cwd must be the absolute working directory of the failing command"
        )
    if request.get("kind") not in {"bug", "friction", "feature"}:
        raise ValueError("kind must be bug, friction, or feature")
    if request.get("impact") not in {"blocker", "friction"}:
        raise ValueError("impact must be blocker or friction")
    argv = request.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(x, str) for x in argv)
    ):
        raise ValueError("argv must be a nonempty array of strings")
    evidence = request.get("evidence", [])
    if not isinstance(evidence, list) or not all(isinstance(x, str) for x in evidence):
        raise ValueError("evidence must be an array of paths")
    return request


def write(path, value, *, replace=False):
    # A private file also keeps supplied local paths out of shared temp files.
    raw = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if not replace:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(raw)
        return
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="Save a JSON request as a local report")
    submit.add_argument("request", type=Path)
    listing = sub.add_parser("list", help="List report summaries without altering them")
    listing.add_argument("--state", choices=("open", "resolved", "all"), default="open")
    resolve = sub.add_parser("resolve", help="Record the tested outcome of a report")
    resolve.add_argument("id")
    resolve.add_argument("--summary", required=True)
    resolve.add_argument("--version", required=True)
    resolve.add_argument("--evidence", action="append", default=[])
    for command in (submit, listing, resolve):
        command.add_argument("--directory")
    args = parser.parse_args()
    root = directory(args.directory)
    try:
        if args.command == "submit":
            request = validate(json.loads(args.request.read_text(encoding="utf-8-sig")))
            root.mkdir(parents=True, exist_ok=True)
            report = dict(
                schema=1,
                id=uuid.uuid4().hex,
                created_at=now(),
                state="open",
                request=request,
            )
            path = root / (report["id"] + ".json")
            write(path, report)
            print(path.resolve())
        elif args.command == "list":
            rows = []
            for path in sorted(root.glob("*.json")):
                report = json.loads(path.read_text(encoding="utf-8"))
                if args.state == "all" or report["state"] == args.state:
                    rows.append(
                        dict(
                            id=report["id"],
                            state=report["state"],
                            title=report["request"]["title"],
                            path=str(path.resolve()),
                        )
                    )
            print(json.dumps(rows, indent=2))
        else:
            if len(args.id) != 32 or any(c not in "0123456789abcdef" for c in args.id):
                raise ValueError("id must be the 32-character report identifier")
            path = root / (args.id + ".json")
            report = json.loads(path.read_text(encoding="utf-8"))
            if report["state"] != "open":
                raise ValueError("report is already resolved")
            report.update(
                state="resolved",
                resolution=dict(
                    at=now(),
                    summary=args.summary,
                    version=args.version,
                    evidence=args.evidence,
                ),
            )
            write(path, report, replace=True)
            print(path.resolve())
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"report_issue: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
