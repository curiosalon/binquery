"""Trace questions over portable SMT-LIB; no checkpoint deserialization."""

from __future__ import annotations

import json
import time

import networkx as nx
import z3

from .model import Invalid, number


def expr(value, bits=64):
    if isinstance(value, dict):
        v = z3.BitVec(value["symbol"], value["bits"])
        if v.size() > bits:
            return z3.Extract(bits - 1, 0, v)
        return z3.ZeroExt(bits - v.size(), v) if v.size() < bits else v
    return z3.BitVecVal(value, bits)


def overlap(address, size, low, length):
    # 65 bits prevents address+size wrapping in the query arithmetic.
    at = expr(address, 65)
    return z3.And(z3.ULT(at, low + length), z3.UGT(at + size, low))


class PathQuery:
    def __init__(self, path, milliseconds):
        self.path = path
        self.solver = z3.Solver()
        self.solver.set(timeout=milliseconds)
        self.solver.from_string(path["smt2"])
        self.calls = 0
        self.unknown = False

    def check(self, predicate):
        self.calls += 1
        self.solver.push()
        self.solver.add(predicate)
        answer = self.solver.check()
        model = self.solver.model() if answer == z3.sat else None
        self.solver.pop()
        if answer == z3.unknown:
            self.unknown = True
        return answer, model

    def writers(self, address, before, *, step=None, recurrent=False):
        """Conditional latest supplier per byte, including same-value stores."""
        remain = z3.BoolVal(True)
        result = []
        writes = [
            e for e in self.path["events"][:before] if step is None or e["step"] < step
        ]
        if recurrent:
            # The previous full cycle precedes this cycle's prefix. Exact
            # closed-state detection establishes identical addresses/values.
            writes = self.path["events"] + [
                e for e in writes if e["step"] > self.path["cycle_start"]
            ]
        for write in reversed(writes):
            if write["kind"] != "write":
                continue
            addr = expr(address, 65) if isinstance(address, (dict, int)) else address
            base = expr(write["address"], 65)
            hit = z3.And(z3.UGE(addr, base), z3.ULT(addr, base + write["size"]))
            guard = z3.And(remain, hit)
            if self.check(guard)[0] != z3.unsat:
                result.append(
                    {
                        "writer": write["id"],
                        "instruction": write["instruction"],
                        "condition": z3.simplify(guard).sexpr(),
                    }
                )
            remain = z3.And(remain, z3.Not(hit))
        if self.check(remain)[0] != z3.unsat:
            result.append(
                {"writer": "initial", "condition": z3.simplify(remain).sexpr()}
            )
        if recurrent:
            result = [dict(row, visit="subsequent cycle") for row in result]
        return result

    def read_writers(self, address, before, event, within=None, occurrence=False):
        result = self.writers(
            address, before, step=event["step"] if event["id"].startswith("x") else None
        )
        start = self.path.get("cycle_start")
        if start is not None and event["step"] > start and not occurrence:
            period = self.path["depth"] - start
            if within is None or event["step"] + period <= within:
                result += self.writers(
                    address,
                    before,
                    step=event["step"] if event["id"].startswith("x") else None,
                    recurrent=True,
                )
        return result


def validate_question(question):
    allowed = {
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
    }
    if not isinstance(question, dict) or set(question) - allowed:
        raise Invalid("Unknown trace question fields")
    q = dict(question)
    if q.get("kind") not in {
        "access",
        "last-write",
        "modified-code",
        "flow",
        "memory-effect",
    }:
        raise Invalid("Choose access, last-write, modified-code, flow or memory-effect")
    shared = {"kind", "path", "entry", "expect", "within_steps"}
    selectors = {
        "access": {"access", "range", "event"},
        "last-write": {"site", "event"},
        "modified-code": {"range", "event"},
        "flow": {"to", "site", "event"},
        "memory-effect": {"range", "to", "effect", "source", "value"},
    }
    unused = {k for k, v in q.items() if v is not None} - shared - selectors[q["kind"]]
    if q["kind"] == "memory-effect":
        if q.get("effect") == "copy" and q.get("value") is not None:
            unused.add("value")
        if q.get("effect") == "fill" and q.get("source") is not None:
            unused.add("source")
    if unused:
        raise Invalid(f"{q['kind']} does not use: {', '.join(sorted(unused))}")
    q.setdefault("expect", "possible")
    if q["expect"] not in {"possible", "never", "always"}:
        raise Invalid("expect must be possible, never or always")
    if q.get("event") and not q.get("path"):
        raise Invalid("An event occurrence requires --path pN")
    for field in ("site", "to", "within_steps"):
        if field in q and q[field] is not None:
            q[field] = number(q[field])
            if q[field] < 0:
                raise Invalid(f"{field} must be nonnegative")
    if q["kind"] in {"access", "modified-code", "memory-effect"}:
        value = q.get("range", "")
        try:
            low, length = (
                map(number, value.split(":"))
                if isinstance(value, str)
                else map(number, value)
            )
        except (ValueError, TypeError):
            raise Invalid("Range requires ADDRESS:SIZE") from None
        if low < 0 or length <= 0 or low + length > 1 << 64:
            raise Invalid("Invalid query range")
        q["range"] = [low, length]
    if q["kind"] == "access" and q.get("access") not in {"read", "write", "both"}:
        raise Invalid("Access question requires read, write or both")
    if q["kind"] == "last-write" and q.get("site") is None and not q.get("event"):
        raise Invalid("Last-write question requires a read --site or --event")
    if q["kind"] == "flow" and q.get("to") is None and q.get("site") is None:
        raise Invalid("Flow question requires --to or --site")
    if q["kind"] == "memory-effect":
        if q.get("to") is None or q.get("effect") not in {"copy", "fill"}:
            raise Invalid(
                "Memory effect requires copy/fill and an initialization boundary --to"
            )
        if q["range"][1] > 65536:
            raise Invalid("Memory-effect extent exceeds 65536 bytes")
        if q["effect"] == "copy":
            q["source"] = number(q.get("source", -1))
            if q["source"] < 0 or q["source"] + q["range"][1] > 1 << 64:
                raise Invalid("Copy requires a valid source address")
            low, size = q["range"]
            if max(low, q["source"]) < min(low + size, q["source"] + size):
                raise Invalid("Overlapping copy is unsupported by memory-effect")
        else:
            q["value"] = number(q.get("value", -1))
            if not 0 <= q["value"] <= 255:
                raise Invalid("Fill requires a byte value")
    return q


def memory_effect(path, question):
    """Exact final byte effects, requiring writes and the supplied boundary."""
    q = question
    if (
        path["outcome"] != "stop"
        or path["stop"] != q["to"]
        or (q.get("within_steps") is not None and path["depth"] > q["within_steps"])
    ):
        return None
    low, size = q["range"]
    initial = {r["address"]: r["value"] for r in path.get("initial_accessed_bytes", [])}
    events = path["events"]
    writes = [e for e in events if e["kind"] == "write"]
    claims = []
    for index in range(size):
        at = low + index
        value, hits = z3.BitVecVal(0, 8), []
        for write in writes:
            base = expr(write["address"], 65)
            hit = z3.And(base <= at, base + write["size"] > at)
            # Architectural memory-event integers are little endian.
            bits = write["size"] * 8
            offset = z3.BitVecVal(at, 65) - base
            shift = (
                z3.ZeroExt(bits - 65, offset)
                if bits >= 65
                else z3.Extract(bits - 1, 0, offset)
            )
            byte = z3.Extract(
                7, 0, z3.LShR(expr(write["value"], write["size"] * 8), shift * 8)
            )
            value = z3.If(hit, byte, value)
            hits.append(hit)
        if q["effect"] == "copy":
            source = q["source"] + index
            if source not in initial:
                return None
            expected = expr(initial[source], 8)
            claims.append(
                z3.Or(
                    *(
                        overlap(e["address"], e["size"], source, 1)
                        for e in events
                        if e["kind"] == "read"
                    )
                )
            )
        else:
            expected = z3.BitVecVal(q["value"], 8)
        claims.extend((z3.Or(*hits), value == expected))
    if q["effect"] == "copy":
        claims.extend(
            z3.Not(overlap(e["address"], e["size"], q["source"], size)) for e in writes
        )
    return z3.And(*claims)


def materialize(value, model):
    if isinstance(value, dict):
        if value.get("undefined"):
            return value
        if "symbol" in value and "bits" in value:
            return model.eval(
                expr(value, value["bits"]), model_completion=True
            ).as_long()
        return {k: materialize(v, model) for k, v in value.items()}
    if isinstance(value, list):
        return [materialize(v, model) for v in value]
    return value


def ask(report, question):
    query_started = time.monotonic()
    q = validate_question(question)
    within = q.get("within_steps")
    matches, witnesses = [], []
    can_match, can_avoid, all_settled = False, False, True
    solver_calls, used = 0, 0
    for path in report["paths"]:
        if (
            q.get("path")
            and path["id"] != q["path"]
            or q.get("entry")
            and path["entry"]["name"] != q["entry"]
        ):
            continue
        used += 1
        if q.get("event") and q["event"] not in {
            e["id"] for e in path["events"] + path["trace"]
        }:
            raise Invalid("No retained occurrence has the selected event ID")
        pq = PathQuery(path, report["limits"]["solver_ms"])
        guards = []
        scope = lambda e: (
            (within is None or e["step"] <= within)
            and (not q.get("event") or e["id"] == q["event"])
        )
        if q["kind"] in {"access", "last-write"}:
            for n, event in enumerate(path["events"]):
                if not scope(event):
                    continue
                if q["kind"] == "access":
                    if q["access"] != "both" and event["kind"] != q["access"]:
                        continue
                    guard = overlap(event["address"], event["size"], *q["range"])
                else:
                    if (
                        event["kind"] != "read"
                        or q.get("site") is not None
                        and event["instruction"] != q["site"]
                    ):
                        continue
                    guard = z3.BoolVal(True)
                guards.append(guard)
                if pq.check(guard)[0] == z3.unsat:
                    continue
                item = dict(
                    event,
                    path=path["id"],
                    entry=path["entry"],
                    condition=z3.simplify(guard).sexpr(),
                )
                if q["kind"] == "last-write":
                    item["bytes"] = [
                        {
                            "offset": i,
                            "writers": pq.read_writers(
                                expr(event["address"], 65) + i,
                                n,
                                event,
                                within,
                                bool(q.get("event")),
                            ),
                        }
                        for i in range(event["size"])
                    ]
                matches.append(item)
        elif q["kind"] == "modified-code":
            for event in path["trace"]:
                if not scope(event):
                    continue
                executed, original = (
                    bytes.fromhex(event["bytes"]),
                    bytes.fromhex(event["initial_bytes"]),
                )
                selected = [
                    (i, b)
                    for i, b in enumerate(executed)
                    if q["range"][0] <= event["instruction"] + i < sum(q["range"])
                ]
                if not selected:
                    continue
                changed = [
                    i for i, b in selected if i >= len(original) or b != original[i]
                ]
                prior = [
                    w
                    for w in path["events"]
                    if w["kind"] == "write" and w["step"] < event["step"]
                ]
                write_guard = z3.Or(
                    *(
                        overlap(
                            w["address"], w["size"], event["instruction"], len(executed)
                        )
                        for w in prior
                    )
                )
                start = path.get("cycle_start")
                repeat = (
                    start is not None
                    and event["step"] > start
                    and not q.get("event")
                    and (
                        within is None
                        or event["step"] + path["depth"] - start <= within
                    )
                )
                if repeat:
                    prior += [
                        w
                        for w in path["events"]
                        if w["kind"] == "write" and w["step"] > start
                    ]
                    write_guard = z3.Or(
                        *(
                            overlap(
                                w["address"],
                                w["size"],
                                event["instruction"],
                                len(executed),
                            )
                            for w in prior
                        )
                    )
                if changed or pq.check(write_guard)[0] == z3.sat:
                    matches.append(
                        dict(
                            event,
                            path=path["id"],
                            entry=path["entry"],
                            changed_offsets=changed,
                            bytes=[
                                {
                                    "offset": i,
                                    "writers": pq.read_writers(
                                        event["instruction"] + i,
                                        len(path["events"]),
                                        event,
                                        within,
                                        bool(q.get("event")),
                                    ),
                                }
                                for i, _ in selected
                            ],
                        )
                    )
                if changed:
                    guards.append(z3.BoolVal(True))
        elif q["kind"] == "memory-effect":
            effect = memory_effect(path, q)
            if effect is None:
                all_settled = False
                continue
            guards.append(effect)
            matches.append(
                dict(
                    id="effect",
                    path=path["id"],
                    entry=path["entry"],
                    instruction=path["stop"],
                    kind=q["effect"],
                    range=q["range"],
                )
            )
        else:
            for event in path["trace"]:
                if (
                    scope(event)
                    and (q.get("to") is None or event["target"] == q["to"])
                    and (q.get("site") is None or event["instruction"] == q["site"])
                ):
                    guards.append(z3.BoolVal(True))
                    matches.append(dict(event, path=path["id"], entry=path["entry"]))
        predicate = z3.Or(*guards)
        yes, model = pq.check(predicate)
        no, counter = pq.check(z3.Not(predicate))
        if (
            q["kind"] == "memory-effect"
            and yes == z3.sat
            and no == z3.sat
            and path.get("unknown_flags")
        ):
            yes = no = z3.unknown
            pq.unknown = True
        settled = (
            path["outcome"] in {"stop", "cycle"}
            or within is not None
            and path["depth"] >= within
        )
        if yes == z3.sat:
            can_match = True
            if sum(w["interaction"] is True for w in witnesses) < 2:
                witnesses.append(
                    {
                        "path": path["id"],
                        "interaction": True,
                        "inputs": materialize(path["inputs"], model),
                        "memory": materialize(path.get("input_memory", []), model),
                        "events": materialize(path["events"], model),
                        "trace": materialize(path["trace"], model),
                        "io": materialize(path["io"], model),
                        "model": str(model),
                    }
                )
        if no == z3.sat and settled:
            can_avoid = True
            if sum(w["interaction"] is False for w in witnesses) < 2:
                witnesses.append(
                    {
                        "path": path["id"],
                        "interaction": False,
                        "inputs": materialize(path["inputs"], counter),
                        "memory": materialize(path.get("input_memory", []), counter),
                        "events": materialize(path["events"], counter),
                        "trace": materialize(path["trace"], counter),
                        "io": materialize(path["io"], counter),
                        "model": str(counter),
                    }
                )
        if not settled and no != z3.unsat or pq.unknown:
            all_settled = False
        solver_calls += pq.calls
    if not used:
        raise Invalid("No retained path matches the selected entry/path")
    if q["expect"] == "possible":
        status = (
            "ESTABLISHED" if can_match else "REFUTED" if all_settled else "INCONCLUSIVE"
        )
    elif q["expect"] == "never":
        status = (
            "REFUTED" if can_match else "ESTABLISHED" if all_settled else "INCONCLUSIVE"
        )
    else:
        status = (
            "REFUTED"
            if can_avoid
            else "ESTABLISHED"
            if all_settled and can_match
            else "INCONCLUSIVE"
        )
    replay_failed = report.get("replay_failed", False)
    # Reserve examples of both directions, and replay the answer's decisive
    # witness first if the configured representative budget is small.
    decisive = q["expect"] != "always"
    witnesses.sort(key=lambda w: w["interaction"] != decisive)
    for ordinal, witness in enumerate(witnesses):
        witness["replay"] = (
            replay_selected(report, witness)
            if ordinal < report["limits"]["replays"]
            else {"status": "not-run", "reason": "Representative replay limit"}
        )
        replay_failed |= witness["replay"].get("matched") is False
    if replay_failed:
        status = "INCONCLUSIVE"
    return {
        "operation": "trace-query",
        "status": status,
        "question": q,
        "scope": f"within {within} steps"
        if within is not None
        else "All admitted executions; unfinished paths remain explicit",
        "meaning": "At least one selected interaction occurs during an execution; always quantifies every admitted execution",
        "matches": matches,
        "witnesses": witnesses,
        "complete_for_question": all_settled,
        "solver_calls": solver_calls,
        "replay_failed": replay_failed,
        "elapsed_seconds": time.monotonic() - query_started,
    }


def replay_selected(report, selected):
    """Replay a query model from JSON, never unpickle checkpoint state."""
    from pathlib import Path

    from .model import digest

    config = report.get("replay_config")
    if not config:
        return {"status": "not-run", "reason": "No replay configuration in this report"}
    try:
        if any(
            digest(Path(path).read_bytes()) != value
            for path, value in config["inputs"].items()
        ):
            return {
                "status": "not-run",
                "reason": "Original inputs changed; portable findings retained",
            }
    except OSError:
        return {
            "status": "not-run",
            "reason": "Original inputs unavailable; portable findings retained",
        }
    path = next(p for p in report["paths"] if p["id"] == selected["path"])
    index = next(
        i for i, e in enumerate(config["entries"]) if e["identity"] == path["entry"]
    )
    from .execution import ObservedAnalysis
    from .execution_replay import replay_witness

    engine = ObservedAnalysis(config, config["entries"][index], index)
    events = []
    for source in selected["events"]:
        event = {k: v for k, v in source.items() if k != "id"}
        if event["kind"] == "read":
            prior = []
            for previous in reversed(events):
                if previous["step"] != event["step"] or previous["kind"] == "write":
                    break
                prior.append(previous)
            if event in prior:
                continue
        events.append(event)
    witness = {
        "registers": selected["inputs"],
        "flags": engine.spec["flags"],
        "memory": [
            {
                "address": e["address"],
                "hex": e["value"].to_bytes(e["size"], "big").hex(),
            }
            for e in selected["memory"]
        ],
        "trace": selected["trace"],
        "io": selected["io"],
        "expected": {"events": events},
        "unknown_flags": path.get("unknown_flags", {}),
    }
    if witness["unknown_flags"]:
        solver = z3.Solver()
        solver.from_string(path["smt2"])
        for name, value in path["inputs"].items():
            solver.add(expr(value) == selected["inputs"][name])
        for original, concrete in zip(path["input_memory"], selected["memory"]):
            solver.add(
                expr(original["value"], original["size"] * 8) == concrete["value"]
            )
        for original, concrete in zip(path["io"], selected["io"]):
            if original["kind"] == "port-in":
                solver.add(
                    expr(original["value"], original["size"] * 8) == concrete["value"]
                )
        witness["smt2"] = solver.to_smt2()
    return replay_witness(engine, witness)


def graph(report, view):
    g = nx.MultiDiGraph()
    if view not in {"flow", "calls", "memory"}:
        raise Invalid("Graph view must be flow, calls or memory")
    for path in report["paths"]:
        prefix = path["id"] + ":"
        if view == "memory":
            pq = PathQuery(path, report["limits"]["solver_ms"])
            for n, event in enumerate(path["events"]):
                if event["kind"] != "read":
                    continue
                target = prefix + event["id"]
                g.add_node(
                    target, label=f"read {event['instruction']:#x}", path=path["id"]
                )
                for i in range(event["size"]):
                    for writer in pq.read_writers(
                        expr(event["address"], 65) + i, n, event
                    ):
                        source = prefix + writer["writer"]
                        g.add_node(source, label=writer["writer"], path=path["id"])
                        g.add_edge(
                            source,
                            target,
                            byte=i,
                            condition=writer["condition"],
                            visit=writer.get("visit", "recorded"),
                        )
        else:
            for e in path["trace"]:
                if view == "calls" and e["kind"] not in {
                    "call",
                    "return",
                    "interrupt",
                    "interrupt-return",
                }:
                    continue
                # Occurrence nodes preserve order: never combine mutually
                # incompatible paths into a claimed executable graph route.
                source, target = prefix + str(e["step"]), prefix + str(e["step"] + 1)
                g.add_node(
                    source,
                    label=f"{e['instruction']:#x}",
                    path=path["id"],
                    entry=path["entry"],
                )
                g.add_node(
                    target,
                    label=f"{e['target']:#x}",
                    path=path["id"],
                    entry=path["entry"],
                )
                g.add_edge(
                    source, target, kind=e["kind"], conditions=path["conditions"]
                )
            if view == "flow" and "cycle_start" in path:
                g.add_edge(
                    prefix + str(path["depth"] + 1),
                    prefix + str(path["cycle_start"] + 1),
                    kind="repeat",
                    conditions=path["conditions"],
                )
    return {
        "operation": "graph",
        "status": "EXPORTED",
        "view": view,
        "scope": "Conditional occurrence graph; paths remain separate",
        "inputs": report["inputs"],
        "entries": report["entries"],
        "paths": [
            {
                k: p[k]
                for k in (
                    "id",
                    "entry",
                    "conditions",
                    "smt2",
                    "outcome",
                    "reason",
                    "depth",
                )
            }
            for p in report["paths"]
        ],
        "nodes": [dict(id=n, **a) for n, a in g.nodes(data=True)],
        "edges": [dict(source=a, target=b, **d) for a, b, d in g.edges(data=True)],
    }


def dot(result):
    lines = ["digraph binquery {"]
    for n in result["nodes"]:
        lines.append(f"  {json.dumps(n['id'])} [label={json.dumps(n['label'])}];")
    for e in result["edges"]:
        label = e.get("kind", f"byte {e.get('byte')}")
        lines.append(
            f"  {json.dumps(e['source'])} -> {json.dumps(e['target'])} [label={json.dumps(label)}];"
        )
    return "\n".join(lines + ["}"])
