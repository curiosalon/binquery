"""Portable guarded expressions, ordered effects and concrete witnesses."""

from __future__ import annotations

from angr import claripy

from .engine import concrete
from .model import digest
from .flags import unknown_symbols


class Encoder:
    def __init__(self, state):
        self.state = state
        self.solver = state.solver._solver.branch()
        self.count = 0

    def value(self, expr):
        if isinstance(expr, (str, int, bool)) or expr is None:
            return expr
        if isinstance(expr, dict):
            return {k: self.value(v) for k, v in expr.items()}
        if isinstance(expr, (tuple, list)):
            return [self.value(v) for v in expr]
        if not expr.symbolic:
            return self.state.solver.eval(expr)
        name = f"bq_observation_{self.count}"
        self.count += 1
        self.solver.add(claripy.BVS(name, expr.size(), explicit_name=True) == expr)
        result = {"symbol": name, "bits": expr.size(), "text": str(expr)}
        unknown = sorted(unknown_symbols(self.state, expr))
        if unknown:
            result["undefined"] = unknown
        return result

    def smt2(self):
        # clarirs emits a nonstandard bvreverse operator. Lower that AST node
        # to standard byte extracts/concatenation before serializing.
        result = claripy.Solver()
        for constraint in self.solver.constraints:
            stack, replacements = [constraint], []
            seen = set()
            while stack:
                node = stack.pop()
                if not hasattr(node, "op") or hash(node) in seen:
                    continue
                seen.add(hash(node))
                stack.extend(node.args)
                if node.op == "Reverse":
                    value = node.args[0]
                    replacements.append(
                        (
                            node,
                            claripy.Concat(
                                *[value[n + 7 : n] for n in range(0, value.size(), 8)]
                            ),
                        )
                    )
            for old, new in replacements:
                constraint = claripy.replace(constraint, old, new)
            result.add(constraint)
        return result.to_smt2()


def witness(engine, state):
    chosen = state.copy()
    expressions = [*engine.input_regs.values(), *(v for _, v in engine.input_memory)]
    expressions += [e["value"] for e in state.globals["io"] if e["kind"] == "port-in"]
    joined = claripy.Concat(*expressions)
    model = chosen.solver.eval(joined)
    for expr in reversed(expressions):
        chosen.add_constraints(expr == (model & ((1 << expr.size()) - 1)))
        model >>= expr.size()
    result = engine.witness(chosen)
    enc = Encoder(chosen)

    def value(expr):
        return (
            enc.value(expr)
            if unknown_symbols(chosen, expr)
            else chosen.solver.eval(expr)
        )

    result["trace"] = [
        {
            k: (
                {n: value(v) for n, v in item.items()}
                if k in {"before", "after", "before_flags", "after_flags"}
                else item
            )
            for k, item in e.items()
        }
        for e in state.globals["trace"]
    ]
    result["io"] = [dict(e, value=value(e["value"])) for e in state.globals["io"]]
    # Replace only indeterminate values, preserving the existing coalesced
    # architectural effects and joint concrete input model.
    if state.globals.get("unknown_flag_bits"):
        effects = []
        for step, kind, site, at, size, v in state.globals["events"]:
            event = dict(
                step=step,
                kind=kind,
                instruction=site,
                address=chosen.solver.eval(at),
                size=size,
                value=value(v),
            )
            if kind == "read":
                prior = []
                for previous in reversed(effects):
                    if previous["step"] != step or previous["kind"] == "write":
                        break
                    prior.append(previous)
                if event in prior:
                    continue
            effects.append(event)
        result["expected"]["events"] = effects
        result["expected"]["registers"] = {
            n: value(getattr(chosen.regs, n)) for n in engine.register_names
        }
    result["unknown_flags"] = state.globals.get("unknown_flag_bits", {})
    result["smt2"] = enc.smt2() if result["unknown_flags"] else ""
    return result


def report(execution, *, replay=True):
    paths = []
    states = [
        *execution.finished,
        *((i, s, "pending", reason) for i, s, reason in execution.pending),
    ]
    for ordinal, (index, state, kind, reason) in enumerate(states):
        engine = execution.engines[index]
        enc = Encoder(state)
        events = []
        for n, (step, mode, site, address, size, value) in enumerate(
            state.globals["events"]
        ):
            events.append(
                {
                    "id": f"m{n}",
                    "step": step,
                    "kind": mode,
                    "instruction": site,
                    "address": enc.value(address),
                    "size": size,
                    "value": enc.value(value),
                }
            )
        trace = enc.value(state.globals["trace"])
        for instruction in trace:
            instruction["id"] = f"x{instruction['step']}"
            at = instruction["instruction"]
            size = len(bytes.fromhex(instruction["bytes"]))
            original = bytearray()
            for byte in range(at, at + size):
                raw = next(
                    (r[byte - a] for a, r in engine.chunks if a <= byte < a + len(r)),
                    None,
                )
                if raw is None:
                    break
                original.append(raw)
            instruction["initial_bytes"] = original.hex()
        row = {
            "id": f"p{ordinal}",
            "entry": engine.entry["identity"],
            "outcome": kind,
            "reason": reason,
            "depth": len(state.globals["path"]),
            "stop": concrete(state, state.regs.ip),
            "conditions": [str(c) for c in state.solver.constraints],
            "inputs": enc.value(engine.input_regs),
            "input_memory": [
                {
                    "address": a + offset,
                    "value": enc.value(
                        v[(size - offset) * 8 - 1 : (size - offset - width) * 8]
                    ),
                    "size": width,
                }
                for a, v in engine.input_memory
                for size in [v.size() // 8]
                for offset in range(0, size, 256)
                for width in [min(256, size - offset)]
            ],
            "registers": enc.value(
                {n: getattr(state.regs, n) for n in engine.register_names}
            ),
            "events": events,
            "trace": trace,
            "io": enc.value(state.globals["io"]),
            "unknown_flags": state.globals.get("unknown_flag_bits", {}),
        }
        # Final bytes that were accessed are observations, not invented extents.
        memory = []
        touched = set()
        accessed = set()
        addresses = {}
        for _, mode, _, address, size, _ in state.globals["events"]:
            key = hash(address)
            if key not in addresses:
                addresses[key] = state.solver.eval_upto(
                    address, execution.config["limits"]["addresses"]
                )
            for at in addresses[key]:
                accessed.update(range(at, at + size))
                if mode == "write":
                    touched.update(range(at, at + size))
        for at in sorted(touched):
            value = state.memory.load(at, 1, inspect=False, disable_actions=True)
            memory.append({"address": at, "value": enc.value(value)})
        row["final_written_bytes"] = memory
        row["initial_accessed_bytes"] = [
            dict(
                address=at,
                value=enc.value(
                    engine.initial.memory.load(
                        at, 1, inspect=False, disable_actions=True
                    )
                ),
            )
            for at in sorted(accessed)
        ]
        if "cycle_start" in state.globals:
            row["cycle_start"] = state.globals["cycle_start"]
        row["smt2"] = enc.smt2()
        row["witness"] = witness(engine, state)
        if replay and trace and kind in {"stop", "cycle", "pending"}:
            key = digest(repr(row["witness"]).encode())
            if (
                key not in execution.replays
                and len(execution.replays) < execution.config["limits"]["replays"]
            ):
                from .execution_replay import replay_witness

                execution.replays[key] = replay_witness(engine, row["witness"])
            row["replay"] = execution.replays.get(
                key, {"status": "not-run", "reason": "Representative replay limit"}
            )
        paths.append(row)
    incomplete = any(p["outcome"] not in {"stop", "cycle"} for p in paths)
    replay_failed = any(r.get("matched") is False for r in execution.replays.values())
    complete = bool(paths) and not incomplete and not replay_failed
    return {
        "schema": 2,
        "operation": "analysis",
        "status": "COMPLETE" if complete else "INCONCLUSIVE",
        "complete": complete,
        "execution_complete": not incomplete,
        "replay_failed": replay_failed,
        "scope": "Declared entries, inputs, mappings and external responses; no asynchronous interrupt schedule",
        "architecture": execution.config["entries"][0]["spec"]["architecture"],
        "inputs": execution.config["inputs"],
        "limits": execution.config["limits"],
        "replay_config": execution.config,
        "entries": [
            {"identity": e["identity"], "mappings": e["mappings"]}
            for e in execution.config["entries"]
        ],
        "paths": paths,
        "issues": [
            {"path": p["id"], "kind": p["outcome"], "reason": p["reason"]}
            for p in paths
            if p["outcome"] not in {"stop", "cycle"}
        ],
        "metrics": {
            "elapsed_seconds": execution.elapsed,
            "symbolic_steps": execution.steps,
            "terminal_paths": len(execution.finished),
            "pending_paths": len(execution.pending),
            "solver_calls": execution.solver_calls,
            "solver_call_scope": "Explicit analysis feasibility/enumeration requests; engine-internal calls are not counted",
            "invocations": execution.invocations,
            "replays": len(execution.replays),
            "replay_failures": sum(
                r.get("matched") is False for r in execution.replays.values()
            ),
        },
    }
