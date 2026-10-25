"""Bounded angr queries on caller supplied machine code and explicit state."""

from __future__ import annotations

import io
import time
from pathlib import Path

import angr
import archinfo
import capstone
from angr import claripy

from .model import Incomplete, Invalid, Unsupported, digest, validate_flags
from .isa import qualify
from .effects import is_memory_arithmetic, normalize_arithmetic
from .flags import before_instruction, after_instruction, require_defined
from .realmode import LANGUAGE, RealModeEngine, architecture

REG16 = "ax bx cx dx si di bp sp cs ds ss es".split()
REG64 = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
FLAGS = {"cf": 0, "pf": 2, "zf": 6, "sf": 7, "if": 9, "df": 10, "of": 11}


def concrete(state, expr):
    if isinstance(expr, int):
        return expr
    values = state.solver.eval_upto(expr, 2)
    if len(values) != 1:
        raise Incomplete("Value required to be unique is symbolic")
    return values[0]


def _uninitialized(name, address, bits, state):
    raise Unsupported(f"Read of undeclared initial state at {address:#x} ({bits} bits)")


def _bounded(state, expr, declaration):
    lo = declaration.get("min", 0)
    hi = declaration.get("max", (1 << expr.size()) - 1)
    if not 0 <= lo <= hi < 1 << expr.size():
        raise Invalid("Unsigned input bounds are outside their declared width")
    state.add_constraints(claripy.UGE(expr, lo), claripy.ULE(expr, hi))


class _TargetReached(Exception):
    pass


class Analysis:
    def __init__(self, binary, spec, namespace="", *, dynamic_code=False):
        self.dynamic_code = dynamic_code
        self.started = time.monotonic()
        self.spec = spec
        self.namespace = namespace
        self.relation_domain = None
        self.fixed_segments = None
        self.fixed_stack = None
        self.binary = Path(binary).resolve()
        self.raw = self.binary.read_bytes()
        self.real = spec.get("architecture") == LANGUAGE
        self.identity = {
            "path": str(self.binary),
            "sha256": digest(self.raw),
            "bytes": len(self.raw),
        }
        self.input_regs = {}
        self.input_memory = []
        self.instructions = {}
        self.chunks = []
        self.leaves = []
        self.target_site = None
        self.target_states = []
        self.issues = []
        self.steps = 0
        self._project()
        self._state()
        self._validate_claims()

    def engine_class(self):
        return RealModeEngine

    def _project(self):
        spec = self.spec
        if self.real and not spec["a20"]:
            raise Unsupported("A20 disabled is not qualified")
        if spec["format"] == "auto":
            self.project = angr.Project(
                str(self.binary), auto_load_libs=False, use_sim_procedures=False
            )
            if (
                self.project.arch.name != "AMD64"
                or spec.get("architecture", "AMD64") != "AMD64"
            ):
                raise Unsupported(
                    "Auto-loaded symbolic execution currently qualified only for AMD64"
                )
        else:
            if not self.real and spec["architecture"] != "AMD64":
                raise Unsupported(
                    "Qualified query architectures: AMD64 and x86:LE:16:Real Mode"
                )
            arch = architecture() if self.real else archinfo.ArchAMD64()
            first = spec["code"][0]
            raw = self._range_bytes(first)
            kwargs = {"engine": self.engine_class()} if self.real else {}
            self.project = angr.Project(
                io.BytesIO(raw),
                arch=arch,
                main_opts={
                    "backend": "blob",
                    "base_addr": first["address"],
                    "entry_point": spec["entry"],
                },
                auto_load_libs=False,
                use_sim_procedures=False,
                selfmodifying_code=self.dynamic_code,
                **kwargs,
            )
        decoder = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_16 if self.real else capstone.CS_MODE_64,
        )
        decoder.detail = True
        for row in spec["code"]:
            if spec["format"] == "auto":
                if "sha256" in row and digest(self.raw) != row["sha256"]:
                    raise Invalid("Input file SHA256 differs from contract")
                try:
                    raw = self.project.loader.memory.load(row["address"], row["size"])
                except KeyError as exc:
                    raise Invalid("Code range is outside loaded image") from exc
            else:
                raw = self._range_bytes(row)
            self.chunks.append((row["address"], raw))
            decoded = (
                [] if self.dynamic_code else list(decoder.disasm(raw, row["address"]))
            )
            if not self.dynamic_code and sum(i.size for i in decoded) != len(raw):
                raise Invalid(
                    "Code range includes undecodable bytes; declare only code"
                )
            for ins in decoded:
                self.instructions[ins.address] = ins
        if not self.dynamic_code and spec["entry"] not in self.instructions:
            raise Invalid("Entry is not a decoded instruction boundary")
        self.stop_map = {row["address"]: row["kind"] for row in spec["stops"]}
        if self.real:
            cs = spec["registers"].get("cs")
            if not isinstance(cs, int):
                raise Invalid("Real mode needs concrete CS")
            domains = []
            for row in spec["code"]:
                segment = row.get("segment", cs)
                if (
                    not segment << 4
                    <= row["address"]
                    < row["address"] + row["size"]
                    <= (segment << 4) + 65536
                ):
                    raise Unsupported("Code wraps the declared CS segment")
                domains.append((segment << 4, (segment << 4) + 65536))
            if any(
                not any(lo <= at < hi for lo, hi in domains) for at in self.stop_map
            ):
                raise Unsupported("Exits must share a declared code segment")
        elif any(
            not 0 <= a < (1 << 47) or a + size > (1 << 47)
            for a, size in [(a, len(raw)) for a, raw in self.chunks]
            + [(a, 1) for a in self.stop_map]
        ):
            raise Unsupported(
                "AMD64 addresses require the lower canonical address range"
            )

    def _range_bytes(self, row):
        raw = Path(row["file"]).read_bytes() if "file" in row else self.raw
        if "sha256" in row and digest(raw) != row["sha256"]:
            raise Invalid("Input file SHA256 differs from contract")
        offset = row["offset"]
        if offset + row["size"] > len(raw):
            raise Invalid("Code range exceeds input file")
        return raw[offset : offset + row["size"]]

    def _state(self):
        spec = self.spec
        validate_flags(spec["flags"])
        memory_limit = 0x110000 if self.real else 1 << 47
        for row in spec["memory"]:
            size = len(bytes.fromhex(row["hex"])) if "hex" in row else row["size"]
            if (
                not 0 <= row["address"] < memory_limit
                or row["address"] + size > memory_limit
            ):
                raise Unsupported("Initial memory outside the qualified address range")
        state = self.project.factory.blank_state(
            addr=spec["entry"],
            add_options={angr.options.SPECIAL_MEMORY_FILL},
            special_memory_filler=_uninitialized,
        )
        self.apply_limits(state)
        self.register_names = REG16 if self.real else REG64
        unexpected = set(spec["registers"]) - set(self.register_names)
        if unexpected:
            raise Invalid(f"Unsupported initial registers: {sorted(unexpected)}")
        if self.real and any(
            type(spec["registers"].get(n)) is not int
            for n in ("cs", "ds", "ss", "es", "sp")
        ):
            raise Invalid("Real mode requires concrete segment registers and SP")
        for name in self.register_names:
            value = spec["registers"].get(name, {"symbolic": True})
            bits = 16 if self.real else 64
            if isinstance(value, dict):
                expr = claripy.BVS(
                    self.namespace + "input_" + name, bits, explicit_name=True
                )
                _bounded(state, expr, value)
            else:
                if not 0 <= value < 1 << bits:
                    raise Invalid("Initial register value exceeds width")
                expr = claripy.BVV(value, bits)
            setattr(state.regs, name, expr)
            self.input_regs[name] = expr
        if self.real:
            for name, bit in FLAGS.items():
                setattr(state.regs, name, (spec["flags"] >> bit) & 1)
            state.regs.af = (spec["flags"] >> 4) & 1
        else:
            state.regs.eflags = spec["flags"]
        for address, raw in self.chunks:
            state.memory.store(address, raw, inspect=False, disable_actions=True)
        for row in spec["memory"]:
            address = row["address"]
            if "hex" in row:
                raw = bytes.fromhex(row["hex"])
                expr = claripy.BVV(raw)
                state.memory.store(address, raw, inspect=False, disable_actions=True)
            else:
                size = row["size"]
                # Byte names preserve aliases and input correspondence across
                # separate analyses, regardless of expression/read order.
                byte_exprs = [
                    claripy.BVS(
                        f"{self.namespace}memory_{address + i:x}", 8, explicit_name=True
                    )
                    for i in range(size)
                ]
                expr = claripy.Concat(*byte_exprs) if size > 1 else byte_exprs[0]
                state.memory.store(address, expr, inspect=False, disable_actions=True)
                _bounded(state, expr.reversed, row)
            self.input_memory.append((address, expr))
        if not state.solver.satisfiable():
            raise Invalid("Initial domain is unsatisfiable")
        state.globals["events"] = ()
        state.globals["path"] = ()
        state.globals["a20"] = spec["a20"]
        state.globals["undefined_flags"] = {}
        initialized = set()
        for address, raw in self.chunks:
            initialized.update(range(address, address + len(raw)))
        for address, expr in self.input_memory:
            initialized.update(range(address, address + expr.size() // 8))
        state.globals["initialized"] = frozenset(initialized)
        state.inspect.b(
            "mem_read", when=angr.BP_BEFORE, action=self._check_read_address
        )
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=self._read)
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=self._write)
        state.inspect.b("exit", when=angr.BP_BEFORE, action=self._exit)
        self.initial = state

    def apply_limits(self, state):
        """Apply execution policies to new or restored machine states."""
        state.solver._solver.timeout = self.spec["limits"]["solver_ms"]
        state.memory.read_strategies = [
            angr.concretization_strategies.SimConcretizationStrategySolutions(
                self.spec["limits"]["addresses"]
            )
        ]
        state.memory.write_strategies = [
            angr.concretization_strategies.SimConcretizationStrategySolutions(
                self.spec["limits"]["addresses"]
            )
        ]

    def _check_read_address(self, state):
        # Stop before angr's memory concretizer rejects an oversized domain.
        # The caller can then retain the state at the instruction boundary.
        limit = self.spec["limits"]["addresses"]
        address = state.inspect.attrs.mem_read_address
        if len(state.solver.eval_upto(address, limit + 1)) > limit:
            raise Incomplete("Memory address enumeration limit")

    def _record(self, state, kind):
        address = getattr(state.inspect.attrs, "mem_" + kind + "_address")
        value = getattr(state.inspect.attrs, "mem_" + kind + "_expr")
        length = getattr(state.inspect.attrs, "mem_" + kind + "_length")
        size = (
            value.size() // 8
            if length is None and value is not None
            else concrete(state, length)
        )
        if value is None or size not in (1, 2, 4, 8):
            raise Unsupported("Unsupported memory event width")
        possible = state.solver.eval_upto(address, self.spec["limits"]["addresses"] + 1)
        if len(possible) > self.spec["limits"]["addresses"]:
            raise Incomplete(
                "Symbolic memory address domain exceeds exhaustive enumeration limit"
            )
        if self.relation_domain is not None and any(
            not any(
                lo <= a and a + size <= lo + length
                for lo, length in self.relation_domain
            )
            for a in possible
        ):
            raise Unsupported(
                "Access leaves named relation RAM and the fixed stack segment"
            )
        if self.real and any(a < 0 or a + size > 0x110000 for a in possible):
            raise Unsupported("Physical access outside qualified real mode RAM")
        if not self.real and any(a < 0 or a + size > (1 << 47) for a in possible):
            raise Unsupported("AMD64 memory outside the lower canonical address range")
        touched = {byte for a in possible for byte in range(a, a + size)}
        initialized = state.globals["initialized"]
        if kind == "read" and not touched <= initialized:
            raise Unsupported(
                "Read outside explicitly initialized or previously written memory"
            )
        if kind == "write":
            if len(possible) != 1 and not touched <= initialized:
                raise Unsupported(
                    "Symbolic write requires an explicitly initialized memory domain"
                )
            if len(possible) == 1:
                state.globals["initialized"] = initialized | touched
        if (
            kind == "write"
            and not self.dynamic_code
            and any(
                a < start + len(raw) and start < a + size
                for a in possible
                for start, raw in self.chunks
            )
        ):
            raise Unsupported("Writes to selected code are unsupported")
        path = state.globals["path"]
        event = (len(path), kind, path[-1], address, size, value)
        state.globals["events"] += (event,)

    def _read(self, state):
        self._record(state, "read")

    def _write(self, state):
        self._record(state, "write")

    def _exit(self, state):
        if (
            self.target_site is not None
            and state.globals["path"][-1] == self.target_site
        ):
            captured = state.copy()
            captured.add_constraints(state.inspect.attrs.exit_guard)
            if captured.solver.satisfiable():
                self.target_states.append((captured, state.inspect.attrs.exit_target))
            raise _TargetReached()
        if len(state.solver.eval_upto(state.inspect.attrs.exit_target, 2)) > 1:
            raise Incomplete(
                "Symbolic indirect control target is not uniquely resolved"
            )

    def read_register(self, state, name):
        if name in self.register_names or (self.real and name in FLAGS):
            if self.real and name in FLAGS:
                require_defined(state, [name])
            return getattr(state.regs, name)
        raise Invalid(f"Unsupported observable register: {name}")

    def _validate_claims(self):
        for row in self.spec["claims"]:
            if row["kind"] in ("preserved", "return_equals"):
                value = self.read_register(self.initial, row["register"])
                if "value" in row and not 0 <= row["value"] < 1 << value.size():
                    raise Invalid("Claim value exceeds register width")
            else:
                ins = self.instructions.get(row["instruction"])
                if ins is None:
                    raise Invalid("Claim instruction is not a decoded code boundary")
                reads = any(
                    op.type == capstone.x86.X86_OP_MEM
                    and op.access & capstone.CS_AC_READ
                    for op in ins.operands
                )
                if not reads and ins.mnemonic not in ("pop", "ret"):
                    raise Invalid(
                        "no_read claim does not name a memory-reading instruction"
                    )

    def qualify(self, ins):
        qualify(ins, self.real)

    def validate_relation_state(self, successor):
        if self.fixed_segments and any(
            successor.solver.satisfiable(
                extra_constraints=[getattr(successor.regs, n) != value]
            )
            for n, value in self.fixed_segments.items()
        ):
            raise Unsupported("Layout relation requires unchanged segment registers")
        if self.fixed_stack:
            low, size = self.fixed_stack
            sp = (claripy.ZeroExt(16, successor.regs.ss) << 4) + claripy.ZeroExt(
                16, successor.regs.sp
            )
            if successor.solver.satisfiable(
                extra_constraints=[
                    claripy.Or(
                        claripy.ULT(sp, low),
                        claripy.UGT(sp, low + size),
                    )
                ]
            ):
                raise Unsupported("SP leaves the fixed relation stack window")

    def step(self, state, ins):
        """Execute one qualified instruction; callers own scheduling and retention."""
        address = ins.address
        path = state.globals["path"]
        if self.project.is_hooked(address):
            raise Unsupported("Implicit or explicit hooked execution is not admitted")
        self.qualify(ins)
        if self.real and ins.mnemonic in ("ljmp", "lcall", "retf"):
            from .transfers import execute

            state.globals["path"] = path + (address,)
            target = execute(state, ins)
            self.steps += 1
            self.validate_relation_state(state)
            if address == self.target_site:
                self.target_states.append((state.copy(), target))
                return []
            elif len(state.solver.eval_upto(target, 2)) != 1:
                raise Incomplete("Symbolic far target needs a target query")
            else:
                state.regs.ip = target
            return [state]
        if (
            self.real
            and ins.mnemonic == "call"
            and concrete(state, state.regs.cs) & 0xFFF
        ):
            raise Unsupported(
                "Near CALL return offsets with a non-64KiB-aligned CS are not qualified"
            )
        flag_context = (
            before_instruction(state, ins, self.spec.get("shift_count", "portable"))
            if self.real
            else None
        )
        state.globals["path"] = path + (address,)
        previous_events = len(state.globals["events"])
        successors = self.project.factory.successors(
            state,
            num_inst=1,
            **({"insn_bytes": bytes(ins.bytes)} if self.dynamic_code else {}),
        )
        self.steps += 1
        if successors.unconstrained_successors:
            raise Incomplete("Unconstrained control flow")
        if self.real:
            for successor in successors.flat_successors:
                events = successor.globals["events"]
                current_events = events[previous_events:]
                after_instruction(successor, ins, flag_context, current_events)
                for segment in ("ds", "es"):
                    if (
                        len(
                            successor.solver.eval_upto(
                                getattr(successor.regs, segment), 2
                            )
                        )
                        != 1
                    ):
                        raise Unsupported("Symbolic DS/ES updates are not qualified")
                self.validate_relation_state(successor)
                if is_memory_arithmetic(ins):
                    normalized = normalize_arithmetic(successor, ins, current_events)
                    successor.globals["events"] = events[:previous_events] + normalized
        if not successors.flat_successors and not successors.unsat_successors:
            raise Incomplete("Path ended without a declared stop")
        return successors.flat_successors

    def explore(self):
        pending = [self.initial]
        while pending:
            if time.monotonic() - self.started > self.spec["limits"]["seconds"]:
                self.issues.append(
                    {"kind": "INCONCLUSIVE", "reason": "Analysis time limit"}
                )
                break
            if len(pending) + len(self.leaves) > self.spec["limits"]["states"]:
                self.issues.append({"kind": "INCONCLUSIVE", "reason": "Path limit"})
                break
            state = pending.pop()
            try:
                address = concrete(state, state.regs.ip)
                if address in self.stop_map:
                    self.leaves.append(state)
                    continue
                path = state.globals["path"]
                if len(path) >= self.spec["limits"]["steps"]:
                    raise Incomplete("Instruction limit; path not completely explored")
                ins = self.instructions.get(address)
                if ins is None:
                    raise Unsupported(
                        f"Control leaves declared code at {address:#x}; unknown call/target"
                    )
                pending.extend(self.step(state, ins))
            except _TargetReached:
                self.steps += 1
                continue
            except (
                Unsupported,
                Incomplete,
                angr.errors.AngrError,
                angr.errors.SimError,
                claripy.errors.ClaripyError,
            ) as exc:
                self.issues.append(
                    {
                        "kind": "UNSUPPORTED"
                        if isinstance(exc, Unsupported)
                        else "INCONCLUSIVE",
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )
        return self

    def witness(self, state, extra=()):
        solved = state.copy()
        solved.add_constraints(*extra)
        expressions = [
            *self.input_regs.values(),
            *(expr for _, expr in self.input_memory),
        ]
        # One joint satisfying model, rather than unrelated eval() assignments.
        joined = claripy.Concat(*expressions)
        value = solved.solver.eval(joined)
        values = []
        for expr in reversed(expressions):
            values.append(value & ((1 << expr.size()) - 1))
            value >>= expr.size()
        values.reverse()
        for expr, selected in zip(expressions, values):
            solved.add_constraints(expr == selected)
        count = len(self.input_regs)
        registers = dict(zip(self.input_regs, values[:count]))
        memory = [
            {
                "address": address,
                "hex": selected.to_bytes(expr.size() // 8, "big").hex(),
            }
            for (address, expr), selected in zip(self.input_memory, values[count:])
        ]
        outputs = {
            n: solved.solver.eval(self.read_register(solved, n))
            for n in self.register_names
        }
        events = []
        for step, kind, ins, addr, size, expr in solved.globals["events"]:
            event = {
                "step": step,
                "kind": kind,
                "instruction": ins,
                "address": solved.solver.eval(addr),
                "size": size,
                "value": solved.solver.eval(expr),
            }
            # SLEIGH may read an operand again while deriving flags. Coalesce
            # identical reads within one architectural instruction, never over
            # a write or an instruction boundary. RAM only; no MMIO claim.
            if kind == "read":
                previous_reads = []
                for previous in reversed(events):
                    if previous["step"] != step or previous["kind"] == "write":
                        break
                    previous_reads.append(previous)
                if event in previous_reads:
                    continue
            events.append(event)
        return {
            "registers": registers,
            "flags": self.spec["flags"],
            "memory": memory,
            "expected": {
                "registers": outputs,
                "stop": concrete(solved, solved.regs.ip),
                "path": list(solved.globals["path"]),
                "events": events,
            },
        }

    def summary(self):
        return {
            "binary": self.identity,
            "architecture": self.project.arch.name,
            "code_ranges": [
                {"address": a, "size": len(raw), "sha256": digest(raw)}
                for a, raw in self.chunks
            ],
            "adapter": "real16-segment-v3" if self.real else "angr-vex",
            "shift_count_policy": self.spec.get("shift_count", "portable")
            if self.real
            else "backend default",
            "flag_policy": "Undefined flag dependencies are unsupported"
            if self.real
            else "backend default",
            "complete": not self.issues and bool(self.leaves),
            "terminal_paths": len(self.leaves),
            "executed_steps": self.steps,
            "issues": self.issues,
            "limits": self.spec["limits"],
            "elapsed_seconds": time.monotonic() - self.started,
        }
