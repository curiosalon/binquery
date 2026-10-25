"""Unix interface for saved execution analyses; existing commands stay separate."""

import json
from pathlib import Path

from .model import Invalid, number


def add_commands(sub):
    c = sub.add_parser(
        "analyze", help="Explore supplied code and retain unfinished machine states"
    )
    c.add_argument("binary", nargs="?")
    c.add_argument("--contract", help="Analysis contract schema 2")
    c.add_argument("--save", help="New local .bq analysis file")
    c.add_argument("--resume", help="Continue a trusted local .bq checkpoint")
    c.add_argument(
        "--steps",
        type=number,
        help="Cumulative per-path depth, maximum 1048576 (default 128)",
    )
    c.add_argument("--json", action="store_true")
    for key in (
        "states",
        "events",
        "variants",
        "checkpoint-mb",
        "replays",
        "seconds",
        "solver-ms",
        "addresses",
    ):
        c.add_argument(
            "--" + key,
            type=number,
            help="Raise the retained " + key + " limit (within supported caps)",
        )
    for name in ("report", "graph"):
        c = sub.add_parser(name, help="Read portable saved analysis " + name)
        c.add_argument("analysis")
        c.add_argument("--json", action="store_true")
        if name == "report":
            c.add_argument(
                "--check-inputs",
                action="store_true",
                help="Check saved input and engine identities without executing or restoring states",
            )
        if name == "graph":
            c.add_argument(
                "--view", choices=("flow", "calls", "memory"), default="flow"
            )
            c.add_argument("--format", choices=("dot", "json"), default="dot")


def add_query_options(c):
    c.add_argument(
        "--analysis", help="Saved analysis; no binary or machine contract needed"
    )
    c.add_argument(
        "--kind",
        choices=("access", "last-write", "modified-code", "flow", "memory-effect"),
    )
    c.add_argument("--effect", choices=("copy", "fill"))
    c.add_argument(
        "--source", type=number, help="Copy source address; size comes from --range"
    )
    c.add_argument("--value", type=number, help="Fill byte value")
    c.add_argument("--access", choices=("read", "write", "both"))
    c.add_argument("--range", metavar="ADDRESS:SIZE")
    c.add_argument("--site", type=number)
    c.add_argument("--to", type=number)
    c.add_argument("--event", help="Occurrence id, e.g. m3 or x2; requires --path")
    c.add_argument("--path", help="Retained path id, e.g. p0")
    c.add_argument("--entry", help="Named starting state")
    c.add_argument(
        "--expect", choices=("possible", "never", "always"), default="possible"
    )
    c.add_argument("--within-steps", type=number)
    c.add_argument(
        "--questions",
        help="JSON array of questions; cannot combine with a single question",
    )


def run(args, bounded=False):
    from .execution_store import read_report

    if args.command == "analyze":
        if args.resume:
            if args.binary or args.contract or args.save:
                raise Invalid(
                    "--resume cannot be combined with binary, --contract or --save"
                )
            filename = args.resume
            saved = read_report(filename)
            limits = saved["limits"]
        else:
            if not args.binary or not args.contract or not args.save:
                raise Invalid("New analysis requires binary, --contract and --save")
            filename = args.save
            if Path(filename).exists():
                raise Invalid(
                    "Analysis already exists; use --resume or a new --save path"
                )
            from .execution_contract import load

            config = load(args.binary, args.contract)
            limits = config["limits"]
        caps = {
            "states": 4096,
            "events": 1000000,
            "variants": 256,
            "checkpoint_mb": 1024,
            "replays": 256,
            "seconds": 300,
            "solver_ms": 60000,
            "addresses": 256,
        }
        overrides = {
            k: getattr(args, k, None)
            for k in caps
            if getattr(args, k, None) is not None
        }
        for key, value in overrides.items():
            if not limits[key] <= value <= caps[key]:
                raise Invalid(
                    f"--{key.replace('_', '-')} must be nondecreasing, maximum {caps[key]}"
                )
        limits.update(overrides)
        if (
            args.resume
            and saved["complete"]
            and all(not p["trace"] or "replay" in p for p in saved["paths"])
            and not overrides
            and args.steps in (None, limits["steps"])
        ):
            from .execution_store import validate_saved

            validate_saved(saved)
            return saved
        if not bounded:
            from .deadline import run_bounded

            # Execution observes its own deadline; leave one solver timeout
            # plus serialization time to retain its final frontier.
            return run_bounded(
                vars(args), limits["seconds"] + limits["solver_ms"] / 1000 + 15
            )
        from .execution import Execution
        from .execution_report import report
        from .execution_store import restore, save

        execution = restore(filename) if args.resume else Execution(config)
        execution.config["limits"].update(overrides)
        for engine in execution.engines:
            engine.spec["limits"].update(
                {k: v for k, v in overrides.items() if k in engine.spec["limits"]}
            )
        if not args.resume:
            save(execution, filename, report(execution, replay=False))
        execution.run(
            args.steps, checkpoint=lambda e: save(e, filename, report(e, replay=False))
        )
        return save(execution, filename, report(execution))
    saved = read_report(args.analysis)
    if args.command == "report":
        if args.check_inputs:
            from .execution_store import validate_saved

            validate_saved(saved)
        return saved
    from .execution_queries import ask, graph

    if args.command == "graph":
        return graph(saved, args.view)
    if args.binary or args.contract:
        raise Invalid("--analysis cannot be combined with a binary or machine contract")
    if args.questions:
        if (
            args.kind
            or args.access
            or args.range
            or args.site is not None
            or args.to is not None
            or args.event
            or args.path
            or args.entry
            or args.within_steps is not None
            or args.expect != "possible"
            or args.effect
            or args.source is not None
            or args.value is not None
        ):
            raise Invalid("--questions cannot be combined with a single question")
        questions = json.loads(Path(args.questions).read_text())
        if not isinstance(questions, list) or not 1 <= len(questions) <= 256:
            raise Invalid("Questions file must contain 1..256 question objects")
        answers = [ask(saved, q) for q in questions]
        return {
            "operation": "trace-queries",
            "status": (
                "INCONCLUSIVE"
                if any(a["status"] == "INCONCLUSIVE" for a in answers)
                else "REFUTED"
                if any(a["status"] == "REFUTED" for a in answers)
                else "ESTABLISHED"
            ),
            "answers": answers,
        }
    q = {
        k: getattr(args, k)
        for k in (
            "kind",
            "access",
            "range",
            "site",
            "to",
            "event",
            "path",
            "entry",
            "expect",
            "within_steps",
            "effect",
            "source",
            "value",
        )
        if getattr(args, k) is not None
    }
    return ask(saved, q)


def human(result):
    print(result.get("status", "INCONCLUSIVE"))
    if result.get("reason"):
        print(result["reason"])
    if result.get("operation") == "analysis":
        m = result["metrics"]
        print(
            f"{len(result['paths'])} paths; {m['pending_paths']} pending; {m['symbolic_steps']} instruction steps; {m['elapsed_seconds']:.3f}s"
        )
        print(
            f"{m['replays']} native replays, {m['replay_failures']} failures; checkpoint {m.get('checkpoint_bytes', 0)} bytes"
        )
        for p in result["paths"]:
            print(
                f"{p['id']} {p['entry']['name']}: {p['outcome']} at {p['stop']:#x}, depth {p['depth']} ({p['reason']})"
            )
            for name, value in p["registers"].items():
                if value != p["inputs"].get(name):
                    print(
                        f"  {name} = {value.get('text') if isinstance(value, dict) else hex(value)}"
                    )
    elif result.get("operation") in {"trace-query", "trace-queries"}:
        for answer in result.get("answers", [result]):
            print(
                f"{answer['status']}: {answer['question']['expect']} {answer['question']['kind']} — {answer['scope']}"
            )
            for e in answer["matches"]:
                print(
                    f"  {e['path']} {e['id']} at {e['instruction']:#x}: {e.get('kind', 'read')}"
                )
                for b in e.get("bytes", []):
                    print(
                        f"    byte +{b['offset']}: "
                        + ", ".join(
                            w["writer"]
                            + (
                                f" at {w['instruction']:#x}"
                                if "instruction" in w
                                else ""
                            )
                            + (f" ({w['visit']})" if "visit" in w else "")
                            for w in b["writers"]
                        )
                    )
    else:
        print(json.dumps(result, indent=2))
