"""Defined-flag contracts for qualified real mode instructions.

SLEIGH's choices for architecturally undefined flags must never establish a
branch or observable property. Track conditional undefinedness across shifts
and later overwrites; this does not introduce arbitrary solver flag inputs.
"""

import capstone
from angr import claripy

from .model import Unsupported

STATUS = {"cf", "pf", "zf", "sf", "of"}
BRANCH_FLAGS = {
    "ja": {"cf", "zf"},
    "jae": {"cf"},
    "jb": {"cf"},
    "jbe": {"cf", "zf"},
    "je": {"zf"},
    "jne": {"zf"},
    "jg": {"zf", "sf", "of"},
    "jge": {"sf", "of"},
    "jl": {"sf", "of"},
    "jle": {"zf", "sf", "of"},
    "js": {"sf"},
    "jns": {"sf"},
    "jo": {"of"},
    "jno": {"of"},
    "jp": {"pf"},
    "jnp": {"pf"},
}


def require_defined(state, names):
    for name in names:
        condition = state.globals.get("undefined_flags", {}).get(
            name, claripy.BoolV(False)
        )
        if state.solver.satisfiable(extra_constraints=[condition]):
            raise Unsupported(
                f"Undefined flag {name.upper()} can affect this observation or branch"
            )


def before_instruction(state, ins, policy):
    require_defined(state, BRANCH_FLAGS.get(ins.mnemonic, ()))
    context = {"undefined": dict(state.globals.get("undefined_flags", {}))}
    if ins.mnemonic in {"shl", "shr"}:
        count = ins.operands[1]
        if count.type == capstone.x86.X86_OP_IMM:
            raw = claripy.BVV(count.imm & 0xFF, 8)
        elif count.type == capstone.x86.X86_OP_REG and ins.reg_name(count.reg) == "cl":
            raw = state.regs.cl
        else:
            raise Unsupported("Shift count must be an immediate or CL")
        if policy == "portable" and state.solver.satisfiable(
            extra_constraints=[claripy.UGT(raw, 31)]
        ):
            raise Unsupported(
                "Counts above 31 require shift_count=masked5; 8086 unmasked shifts are not qualified"
            )
        operand = ins.operands[0]
        context.update(
            count=raw & 31,
            bits=operand.size * 8,
            old_of=state.regs.of,
            old_value=getattr(state.regs, ins.reg_name(operand.reg))
            if operand.type == capstone.x86.X86_OP_REG
            else None,
        )
    return context


def after_instruction(state, ins, context, events):
    undefined = context["undefined"].copy()
    mnemonic = ins.mnemonic
    defines, invalidates = set(), set()
    if mnemonic in {"add", "sub", "cmp", "and", "or", "xor", "test"}:
        defines = STATUS
    elif mnemonic in {"inc", "dec"}:
        defines = STATUS - {"cf"}
    elif mnemonic in {"cld", "std"}:
        defines = {"df"}
    elif mnemonic == "mul":
        defines, invalidates = {"cf", "of"}, {"pf", "zf", "sf"}
    elif mnemonic in {"shl", "shr"}:
        count = context["count"]
        zero = count == 0
        for name in STATUS:
            old = undefined.get(name, claripy.BoolV(False))
            bad = claripy.BoolV(False)
            if name == "cf":
                bad = claripy.UGE(count, context["bits"])
            elif name == "of":
                bad = claripy.UGT(count, 1)
            undefined[name] = claripy.Or(claripy.And(zero, old), bad)
        if mnemonic == "shr":
            # Pinned SLEIGH incorrectly sets OF to zero for count=1 and to the
            # old sign bit for other counts. Intel SDM: preserve at zero, old
            # MSB at one, undefined above one. Repair only this defined flag.
            old_value = context["old_value"]
            if old_value is None:
                reads = [e for e in events if e[1] == "read"]
                if not reads:
                    raise Unsupported("SHR memory operand has no recorded input read")
                old_value = reads[0][5]
            sign = claripy.ZeroExt(
                context["old_of"].size() - 1, old_value[context["bits"] - 1]
            )
            state.regs.of = claripy.If(
                zero, context["old_of"], claripy.If(count == 1, sign, state.regs.of)
            )
    for name in defines:
        undefined[name] = claripy.BoolV(False)
    for name in invalidates:
        undefined[name] = claripy.BoolV(True)
    state.globals["undefined_flags"] = undefined
