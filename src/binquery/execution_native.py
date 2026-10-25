"""Analysis-only real-mode protocols and explicit device inputs.

Ordinary instructions continue through the existing SLEIGH engine. Interrupt
frames use the architecture's IVT and real stack, never host service stubs.
"""

import capstone
from angr import claripy

from .engine import FLAGS, concrete
from .flags import saved_flag, unknown_symbols, require_known
from .model import Unsupported
from .realmode import RealModeEngine
from .transfers import linear


class ObservedRealModeEngine(RealModeEngine):
    def _execute_load(self):
        segment = self.state.globals.get("xlat_segment")
        if segment is None:
            return super()._execute_load()
        # Pinned SLEIGH XLAT computes the wrapped BX+AL offset but omits
        # its segment base. Repair that address; keep the lifter's operation.
        op = self._current_op
        if op.inputs[0].getSpaceFromConst().name != "ram" or op.output.size != 1:
            raise Unsupported("Unexpected XLAT p-code load")
        offset = self._get_value(op.inputs[1])
        address = linear(getattr(self.state.regs, segment), offset[15:0])
        self._set_value(op.output, self.state.memory.load(address, 1))

    def _execute_callother(self):
        op = self._current_op
        name = op.inputs[0].getUserDefinedOpName()
        if name not in ("in", "out"):
            return super()._execute_callother()
        state = self.state
        port = concrete(state, self._get_value(op.inputs[1]))
        width = op.output.size if name == "in" else op.inputs[2].size
        rule = next(
            (
                p
                for p in state.globals["ports"]
                if (p["port"], p["width"]) == (port, width)
            ),
            None,
        )
        if rule is None:
            raise Unsupported(f"Undeclared {name} port {port:#x}, width {width}")
        counts = dict(state.globals.get("port_counts", {}))
        key = (port, width)
        index = counts.get(key, 0)
        if name == "in":
            if "reads" in rule:
                if index >= len(rule["reads"]):
                    raise Unsupported(f"Port {port:#x} response sequence exhausted")
                value = claripy.BVV(rule["reads"][index], width * 8)
            elif "domain" in rule:
                value = claripy.BVS(
                    f"port_{port:x}_{width}_{index}", width * 8, explicit_name=True
                )
                state.add_constraints(claripy.Or(*(value == v for v in rule["domain"])))
            else:
                raise Unsupported(f"Port {port:#x} has no declared read responses")
            counts[key] = index + 1
            state.globals["port_counts"] = counts
            self._set_value(op.output, value)
        else:
            if not rule.get("write", False):
                raise Unsupported(f"Port {port:#x} writes are not declared")
            value = self._get_value(op.inputs[2])
            require_known(state, value, "port output")
        state.globals["io"] += (
            {
                "step": len(state.globals["path"]),
                "kind": "port-" + name,
                "instruction": state.globals["path"][-1],
                "port": port,
                "size": width,
                "value": value,
            },
        )


def qualify_extra(ins):
    if ins.mnemonic not in {
        "in",
        "out",
        "cli",
        "sti",
        "loop",
        "loope",
        "loopne",
        "jcxz",
        "int",
        "iret",
        "pushf",
        "popf",
        "stosb",
        "stosw",
        "lodsb",
        "lodsw",
        "xlatb",
    }:
        return False
    allowed_segment = ins.mnemonic in {"lodsb", "lodsw", "xlatb"} and ins.prefix[1] in {
        0,
        0x26,
        0x2E,
        0x36,
        0x3E,
    }
    if (
        any(ins.prefix[i] for i in (0, 2, 3))
        or (ins.prefix[1] and not allowed_segment)
        or any(o.size > 2 for o in ins.operands)
    ):
        raise Unsupported("Native protocol requires unprefixed 16-bit operands")
    return True


def native_transfer(state, ins, vectors):
    """Correct segmented CALL/RET and real-mode INT/IRET frames."""

    def push(value):
        state.regs.sp -= 2
        state.memory.store(
            linear(state.regs.ss, state.regs.sp), value, endness="Iend_LE"
        )

    def pop():
        value = state.memory.load(
            linear(state.regs.ss, state.regs.sp), 2, endness="Iend_LE"
        )
        state.regs.sp += 2
        return value

    def flags():
        value = claripy.BVV(2, 16)
        for name, bit in (FLAGS | {"af": 4}).items():
            v = saved_flag(state, name)
            value |= claripy.ZeroExt(16 - v.size(), v) << bit
        return value

    def setflags(value):
        if state.solver.satisfiable(extra_constraints=[value & ~0xED7 != 0]):
            raise Unsupported("Restored flags require unsupported processor state")
        for name, bit in (FLAGS | {"af": 4}).items():
            dest = getattr(state.regs, name)
            setattr(state.regs, name, claripy.ZeroExt(dest.size() - 1, value[bit:bit]))
        state.globals["undefined_flags"] = {
            name: claripy.BoolV(bool(unknown_symbols(state, getattr(state.regs, name))))
            for name in (FLAGS | {"af": 4})
        }
        state.globals["pending_flag_bits"] = {
            name: claripy.BoolV(False) for name in FLAGS | {"af": 4}
        }

    if ins.mnemonic == "int":
        vector = ins.operands[0].imm
        if vector not in vectors:
            raise Unsupported(f"Interrupt {vector:#x} handler/schedule is not supplied")
        f = flags()
        push(f)
        push(state.regs.cs)
        push(
            claripy.BVV(
                (ins.address + ins.size - concrete(state, state.regs.cs) * 16) & 65535,
                16,
            )
        )
        state.regs.cs = state.memory.load(vector * 4 + 2, 2, endness="Iend_LE")
        offset = state.memory.load(vector * 4, 2, endness="Iend_LE")
        setattr(state.regs, "if", 0)
        return linear(state.regs.cs, offset)
    if ins.mnemonic == "iret":
        offset, segment, f = pop(), pop(), pop()
        state.regs.cs = segment
        setflags(f)
        return linear(segment, offset)
    if ins.mnemonic == "pushf":
        push(flags())
        return claripy.BVV(ins.address + ins.size, 32)
    if ins.mnemonic == "popf":
        setflags(pop())
        return claripy.BVV(ins.address + ins.size, 32)
    if ins.mnemonic == "ret":
        offset = pop()
        state.regs.sp += ins.operands[0].imm if ins.operands else 0
        return linear(state.regs.cs, offset)
    if ins.mnemonic == "call":
        op = ins.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            offset = (
                ins.address
                + ins.size
                - concrete(state, state.regs.cs) * 16
                + int.from_bytes(bytes(ins.bytes)[-2:], "little", signed=True)
            ) & 65535
            target = linear(state.regs.cs, claripy.BVV(offset, 16))
        elif op.type == capstone.x86.X86_OP_REG:
            target = linear(state.regs.cs, getattr(state.regs, ins.reg_name(op.reg)))
        else:
            mem = op.mem
            at = claripy.BVV(mem.disp & 65535, 16)
            for reg in (mem.base, mem.index):
                if reg:
                    at += getattr(state.regs, ins.reg_name(reg))
            seg = (
                ins.reg_name(mem.segment)
                if mem.segment
                else ("ss" if ins.reg_name(mem.base) == "bp" else "ds")
            )
            offset = state.memory.load(
                linear(getattr(state.regs, seg), at), 2, endness="Iend_LE"
            )
            target = linear(state.regs.cs, offset)
        push(
            claripy.BVV(
                (ins.address + ins.size - concrete(state, state.regs.cs) * 16) & 65535,
                16,
            )
        )
        return target
    raise Unsupported("Unknown native transfer")
