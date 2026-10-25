"""Real-mode far control transfers, checked independently by native replay.

SLEIGH's current indirect LJMP lift drops the segment word. Keep this small
machine adapter separate from application queries and never substitute helpers.
"""

import capstone
from angr import claripy
from .model import Unsupported

FAR = {"ljmp", "lcall", "retf"}


def qualify_far(ins):
    if ins.mnemonic not in FAR:
        return False
    if any(p not in (0, 0x26, 0x2E, 0x36, 0x3E) for p in ins.prefix):
        raise Unsupported("Far transfer has an unsupported operand/address prefix")
    if ins.mnemonic == "retf":
        if len(ins.operands) > 1 or any(
            o.type != capstone.x86.X86_OP_IMM for o in ins.operands
        ):
            raise Unsupported("Unsupported far return form")
    elif len(ins.operands) == 1 and ins.operands[0].type == capstone.x86.X86_OP_MEM:
        op = ins.operands[0]
        if op.size != 4:
            raise Unsupported("Far memory pointer must have two 16-bit words")
        if any(
            ins.reg_name(r) not in {"bx", "bp", "si", "di", "cs", "ds", "es", "ss"}
            for r in (op.mem.base, op.mem.index, op.mem.segment)
            if r
        ):
            raise Unsupported("Unsupported far pointer addressing register")
    elif len(ins.operands) != 2 or any(
        o.type != capstone.x86.X86_OP_IMM or not 0 <= o.imm <= 65535
        for o in ins.operands
    ):
        raise Unsupported("Unsupported far destination")
    return True


def linear(segment, offset):
    return (claripy.ZeroExt(16, segment) << 4) + claripy.ZeroExt(16, offset)


def execute(state, ins):
    def word(address):
        return state.memory.load(address, 2, endness="Iend_LE")

    if ins.mnemonic == "retf":
        offset = word(linear(state.regs.ss, state.regs.sp))
        segment = word(linear(state.regs.ss, state.regs.sp + 2))
        state.regs.sp = state.regs.sp + 4 + (ins.operands[0].imm if ins.operands else 0)
    elif len(ins.operands) == 2:
        segment = claripy.BVV(ins.operands[0].imm, 16)
        offset = claripy.BVV(ins.operands[1].imm, 16)
    else:
        mem = ins.operands[0].mem
        at = claripy.BVV(mem.disp & 65535, 16)
        for reg in (mem.base, mem.index):
            if reg:
                at = at + getattr(state.regs, ins.reg_name(reg))
        name = (
            ins.reg_name(mem.segment)
            if mem.segment
            else ("ss" if ins.reg_name(mem.base) == "bp" else "ds")
        )
        address = linear(getattr(state.regs, name), at)
        offset = word(address)
        segment = word(address + 2)
    if ins.mnemonic == "lcall":
        saved_cs = state.regs.cs
        # Instruction locations are physical; the pushed return is a CS offset.
        return_offset = (
            claripy.BVV(ins.address + ins.size, 32)
            - (claripy.ZeroExt(16, saved_cs) << 4)
        )[15:0]
        for value in (saved_cs, return_offset):
            state.regs.sp = state.regs.sp - 2
            state.memory.store(
                linear(state.regs.ss, state.regs.sp), value, endness="Iend_LE"
            )
    state.regs.cs = segment
    state.globals["far_target"] = (segment, offset)
    return linear(segment, offset)
