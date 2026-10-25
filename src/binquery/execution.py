"""Fair, resumable instruction-boundary execution using the existing engine."""

from __future__ import annotations

import hashlib
import time
from collections import deque

import angr
import capstone
from angr import claripy

from .engine import Analysis, concrete
from .execution_native import ObservedRealModeEngine, native_transfer, qualify_extra
from .flags import require_defined, require_known, unknown_symbols
from .model import Incomplete, Invalid, Unsupported

ERRORS = (Unsupported, Incomplete, angr.errors.AngrError, claripy.errors.ClaripyError)


class ObservedAnalysis(Analysis):
    def __init__(self, config, entry, index):
        self.config = config
        self.entry = entry
        self.solver_calls = 0
        super().__init__(
            config["binary"],
            entry["spec"],
            namespace=f"entry{index}_",
            dynamic_code=True,
        )
        for key, value in {
            "trace": (),
            "io": (),
            "ports": tuple(config["ports"]),
            "port_counts": {},
            "cycles": (),
        }.items():
            self.initial.globals[key] = value
        self.install_hooks(self.initial)

    def engine_class(self):
        return ObservedRealModeEngine

    def install_hooks(self, state):
        # SimState serialization intentionally omits inspection breakpoints.
        if state.has_plugin("inspect"):
            state.release_plugin("inspect")
        state.inspect.b(
            "mem_read", when=angr.BP_BEFORE, action=self._check_read_address
        )
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=self._read)
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=self._write)
        state.inspect.b("exit", when=angr.BP_BEFORE, action=self._exit)
        state.project = self.project
        self.apply_limits(state)

    def qualify(self, ins):
        if self.real and qualify_extra(ins):
            return
        super().qualify(ins)

    def _exit(self, state):
        # angr enumerates finite targets. Unconstrained successors remain an
        # unfinished boundary; they are never discarded as impossible paths.
        require_known(state, state.inspect.attrs.exit_guard, "control-flow condition")
        require_known(state, state.inspect.attrs.exit_target, "control-flow target")

    def permitted(self, address, size, mode):
        return all(
            any(
                m["address"] <= at < m["address"] + m["size"]
                and mode in m["permissions"]
                for m in self.entry["mappings"]
            )
            for at in range(address, address + size)
        )

    def _record(self, state, kind):
        address = getattr(state.inspect.attrs, "mem_" + kind + "_address")
        require_known(state, address, "memory address")
        value = getattr(state.inspect.attrs, "mem_" + kind + "_expr")
        length = getattr(state.inspect.attrs, "mem_" + kind + "_length")
        size = (
            value.size() // 8
            if length is None and value is not None
            else concrete(state, length)
        )
        self.solver_calls += 1
        addresses = state.solver.eval_upto(
            address, self.spec["limits"]["addresses"] + 1
        )
        if len(addresses) > self.spec["limits"]["addresses"]:
            raise Incomplete("Memory address enumeration limit")
        for at in addresses:
            if not self.permitted(at, size, "r" if kind == "read" else "w"):
                raise Unsupported(
                    f"{kind} permission/mapping violation at {at:#x}, {size} bytes"
                )
        super()._record(state, kind)

    def variants(self, state):
        address = concrete(state, state.regs.ip)
        available = 0
        while available < 15 and self.permitted(address + available, 1, "x"):
            available += 1
        if not available:
            raise Unsupported(f"Execution leaves supplied code at {address:#x}")
        decoder = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_16 if self.real else capstone.CS_MODE_64,
        )
        decoder.detail = True
        remainder, variants = state.copy(), []
        for _ in range(self.config["limits"]["variants"]):
            self.solver_calls += 1
            if not remainder.solver.satisfiable():
                return variants, None
            expr = remainder.memory.load(
                address, available, inspect=False, disable_actions=True
            )
            # One joint assignment, never separately chosen symbolic bytes.
            self.solver_calls += 1
            raw = remainder.solver.eval(expr).to_bytes(available, "big")
            ins = next(decoder.disasm(raw, address, count=1), None)
            size = ins.size if ins is not None else available
            prefix = remainder.memory.load(
                address, size, inspect=False, disable_actions=True
            )
            require_known(remainder, prefix, "instruction encoding")
            condition = prefix == claripy.BVV(raw[:size])
            selected = remainder.copy()
            selected.add_constraints(condition)
            variants.append((selected, ins))
            remainder.add_constraints(claripy.Not(condition))
        self.solver_calls += 1
        return variants, remainder if remainder.solver.satisfiable() else None

    def flags(self, state):
        if not self.real:
            return {}
        from .engine import FLAGS

        return {
            name: getattr(state.regs, name)
            for name in set(FLAGS) | {"af"}
            if not state.solver.satisfiable(
                extra_constraints=[
                    state.globals.get("undefined_flags", {}).get(
                        name, claripy.BoolV(False)
                    )
                ]
            )
            and not unknown_symbols(state, getattr(state.regs, name))
        }

    def execute(self, state, ins):
        state.globals["xlat_segment"] = (
            {0: "ds", 0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds"}.get(ins.prefix[1])
            if self.real and ins.mnemonic == "xlatb"
            else None
        )
        before_flags = self.flags(state)
        before = {n: getattr(state.regs, n) for n in self.register_names}
        if self.real:
            require_defined(
                state, {"zf"} if ins.mnemonic in {"loope", "loopne"} else ()
            )
        self.qualify(ins)
        if self.real and ins.mnemonic in {
            "call",
            "ret",
            "int",
            "iret",
            "pushf",
            "popf",
        }:
            state.globals["path"] += (ins.address,)
            state.regs.ip = native_transfer(state, ins, self.config["interrupts"])
            self.steps += 1
            successors = [state]
        elif self.real and ins.mnemonic in {"lcall", "ljmp", "retf"}:
            from .transfers import execute

            state.globals["path"] += (ins.address,)
            state.regs.ip = execute(state, ins)
            self.steps += 1
            successors = [state]
        else:
            successors = super().step(state, ins)
        expanded = []
        for successor in successors:
            require_known(successor, successor.regs.ip, "control-flow target")
            if self.real and ins.mnemonic not in {
                "lcall",
                "ljmp",
                "retf",
                "int",
                "iret",
            }:
                from .transfers import linear

                base = claripy.ZeroExt(16, successor.regs.cs) << 4
                successor.regs.ip = linear(
                    successor.regs.cs, (successor.regs.ip - base)[15:0]
                )
            self.solver_calls += 1
            targets = successor.solver.eval_upto(
                successor.regs.ip, self.spec["limits"]["addresses"] + 1
            )
            if len(targets) > self.spec["limits"]["addresses"]:
                raise Incomplete("Control target enumeration limit")
            for target in sorted(targets):
                child = successor.copy()
                child.add_constraints(child.regs.ip == target)
                child.regs.ip = target
                kind = (
                    "interrupt"
                    if ins.mnemonic == "int"
                    else "interrupt-return"
                    if ins.mnemonic == "iret"
                    else "call"
                    if ins.mnemonic in {"call", "lcall"}
                    else "return"
                    if ins.mnemonic in {"ret", "retf"}
                    else "jump"
                    if ins.mnemonic in {"jmp", "ljmp"}
                    else "branch"
                    if ins.group(capstone.CS_GRP_JUMP)
                    or ins.mnemonic.startswith("loop")
                    else "fallthrough"
                )
                row = {
                    "step": len(child.globals["path"]),
                    "instruction": ins.address,
                    "target": target,
                    "kind": kind,
                    "bytes": bytes(ins.bytes).hex(),
                    "mnemonic": ins.mnemonic,
                    "operands": ins.op_str,
                    "before": before,
                    "before_flags": before_flags,
                    "after_flags": self.flags(child),
                    "after": {n: getattr(child.regs, n) for n in self.register_names},
                }
                if self.real:
                    row["segment"] = concrete(state, before["cs"])
                    row["offset"] = (ins.address - row["segment"] * 16) & 65535
                    row["target_segment"] = concrete(child, child.regs.cs)
                    row["target_offset"] = (target - row["target_segment"] * 16) & 65535
                child.globals["trace"] += (row,)
                expanded.append(child)
        return expanded

    def fingerprint(self, state):
        # Only literal closed states: no symbolic registers, flags, memory or
        # external response domains. Hash all initialized RAM, not just writes.
        if self.config["ports"]:
            return None
        regs = [getattr(state.regs, n) for n in self.register_names]
        regs += [state.regs.ip]
        regs += (
            [
                getattr(state.regs, n)
                for n in ("cf", "pf", "af", "zf", "sf", "of", "df", "if")
            ]
            if self.real
            else [state.regs.eflags]
        )
        if any(r.symbolic for r in regs):
            return None
        h = hashlib.sha256()
        h.update(repr([state.solver.eval(r) for r in regs]).encode())
        h.update(repr(state.globals.get("undefined_flags", {})).encode())
        addresses = sorted(state.globals["initialized"])
        # Adjacent bytes in one read avoids per-byte engine calls.
        groups = []
        for at in addresses:
            if groups and at == groups[-1][1]:
                groups[-1][1] += 1
            else:
                groups.append([at, at + 1])
        for start, end in groups:
            value = state.memory.load(
                start, end - start, inspect=False, disable_actions=True
            )
            if value.symbolic:
                return None
            h.update(start.to_bytes(8, "little"))
            h.update(state.solver.eval(value).to_bytes(end - start, "big"))
        return h.hexdigest()


class Execution:
    def __init__(self, config):
        self.config = config
        self.engines = [
            ObservedAnalysis(config, entry, i)
            for i, entry in enumerate(config["entries"])
        ]
        self.pending = [(i, e.initial, "ready") for i, e in enumerate(self.engines)]
        self.finished = []
        self.elapsed = 0.0
        self.steps = 0
        self.solver_calls = 0
        self.invocations = 0
        self.replays = {}

    def advance(self, index, original):
        """One work item is atomic: a rejected/interrupted step keeps its input."""
        engine = self.engines[index]
        address = concrete(original, original.regs.ip)
        if address in engine.stop_map:
            return [], [(index, original, "stop", engine.stop_map[address])], [], 0
        if len(original.globals["path"]) >= self.config["limits"]["steps"]:
            return [], [], [(index, original, "instruction limit")], 0
        variants, remainder = engine.variants(original)
        ready, finished, paused, steps = [], [], [], 0
        if remainder is not None:
            paused.append((index, remainder, "instruction variant limit"))
        for state, ins in variants:
            if ins is None:
                finished.append(
                    (
                        index,
                        state,
                        "unsupported",
                        "Undecodable current instruction bytes",
                    )
                )
                continue
            try:
                fingerprint = engine.fingerprint(state)
                seen = state.globals["cycles"]
                if fingerprint is not None and any(
                    fingerprint == f for f, depth in seen
                ):
                    state.globals["cycle_start"] = next(
                        depth for f, depth in seen if f == fingerprint
                    )
                    finished.append(
                        (
                            index,
                            state,
                            "cycle",
                            "Exact closed deterministic state repeated",
                        )
                    )
                    continue
                work = state.copy()
                if fingerprint is not None:
                    work.globals["cycles"] = seen + (
                        (fingerprint, len(state.globals["path"])),
                    )
                children = engine.execute(work, ins)
                steps += 1
                ready.extend((index, child, "ready") for child in children)
            except Incomplete as exc:
                paused.append((index, state, str(exc)))
            except ERRORS as exc:
                finished.append(
                    (
                        index,
                        state,
                        "unsupported" if isinstance(exc, Unsupported) else "incomplete",
                        str(exc),
                    )
                )
        return ready, finished, paused, steps

    def run(self, steps=None, checkpoint=None):
        if steps is not None:
            if (
                not 0 < steps <= 1048576
                or steps < self.config["limits"]["steps"]
                and self.invocations
            ):
                raise Invalid("--steps must be a nondecreasing ceiling in 1..1048576")
            self.config["limits"]["steps"] = steps
        limit = self.config["limits"]
        for e in self.engines:
            e.config = self.config
            e.spec["limits"].update(
                {k: v for k, v in limit.items() if k in e.spec["limits"]}
            )
        for index, state, *_ in [*self.pending, *self.finished]:
            self.engines[index].apply_limits(state)
        start = last_save = time.monotonic()
        pending, paused = deque(self.pending), []
        self.pending = []
        self.invocations += 1
        active = None
        try:
            while pending:
                if time.monotonic() - start >= limit["seconds"]:
                    paused.extend((i, s, "time limit") for i, s, _ in pending)
                    pending.clear()
                    break
                if len(pending) + len(paused) + len(self.finished) > limit["states"]:
                    paused.extend((i, s, "path limit") for i, s, _ in pending)
                    pending.clear()
                    break
                active = pending.popleft()
                index, original, _ = active
                try:
                    event_count = sum(
                        len(s.globals["events"])
                        + len(s.globals["trace"])
                        + len(s.globals["io"])
                        for _, s, *_ in [*pending, *paused, *self.finished, active]
                    )
                    if event_count >= limit["events"]:
                        paused.append((index, original, "retained event limit"))
                    else:
                        ready, finished, waiting, count = self.advance(index, original)
                        proposed = [
                            *pending,
                            *paused,
                            *self.finished,
                            *ready,
                            *finished,
                            *waiting,
                        ]
                        size = sum(
                            len(s.globals["events"])
                            + len(s.globals["trace"])
                            + len(s.globals["io"])
                            for _, s, *_ in proposed
                        )
                        if size > limit["events"] or len(proposed) > limit["states"]:
                            paused.append(
                                (index, original, "retained event/path limit")
                            )
                        else:
                            pending.extend(ready)
                            self.finished.extend(finished)
                            paused.extend(waiting)
                            self.steps += count
                except Incomplete as exc:
                    paused.append((index, original, str(exc)))
                except ERRORS as exc:
                    self.finished.append(
                        (
                            index,
                            original,
                            "unsupported"
                            if isinstance(exc, Unsupported)
                            else "incomplete",
                            str(exc),
                        )
                    )
                active = None
                if checkpoint and time.monotonic() - last_save >= 1:
                    self.pending = [*paused, *pending]
                    checkpoint(self)
                    last_save = time.monotonic()
        except KeyboardInterrupt:
            if active is not None:
                i, s, _ = active
                paused.append((i, s, "interrupted"))
            paused.extend((i, s, "interrupted") for i, s, _ in pending)
            pending.clear()
        finally:
            self.pending = [*paused, *pending]
            self.elapsed += time.monotonic() - start
            self.solver_calls += sum(e.solver_calls for e in self.engines)
            for e in self.engines:
                e.solver_calls = 0
        return self
