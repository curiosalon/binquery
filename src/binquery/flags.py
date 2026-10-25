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
        require_known(state, getattr(state.regs, name), "flag " + name.upper())
        condition = state.globals.get("undefined_flags", {}).get(
            name, claripy.BoolV(False)
        )
        if state.solver.satisfiable(extra_constraints=[condition]):
            raise Unsupported(
                f"Undefined flag {name.upper()} can affect this observation or branch"
            )


def unknown_symbols(state, value):
    """Only analysis-created undefined bits, not ordinary symbolic inputs."""
    origins = state.globals.get("unknown_flag_bits", {})
    if not origins or not hasattr(value, "variables"):
        return set()
    return set(claripy.simplify(value).variables) & set(origins)


def require_known(state, value, use):
    unknown = unknown_symbols(state, value)
    if unknown:
        names = sorted(
            {state.globals["unknown_flag_bits"][s]["flag"].upper() for s in unknown}
        )
        raise Unsupported(
            "Undefined processor bit (" + ", ".join(names) + ") affects " + use
        )


def saved_flag(state, name):
    """Materialize an undefined bit only when it is actually saved."""
    value = getattr(state.regs, name)
    condition = state.globals.get("pending_flag_bits", {}).get(
        name, state.globals.get("undefined_flags", {}).get(name, claripy.BoolV(False))
    )
    if not state.solver.satisfiable(extra_constraints=[condition]):
        return value
    origins = dict(state.globals.get("unknown_flag_bits", {}))
    symbol = f"bq_undefined_{len(origins)}_{name}"
    bit = claripy.BVS(symbol, 1, explicit_name=True)
    origins[symbol] = dict(
        flag=name,
        step=len(state.globals["path"]),
        instruction=state.globals["path"][-1],
        origin="undefined flag saved before instruction",
    )
    state.globals["unknown_flag_bits"] = origins
    pending = dict(state.globals.get("pending_flag_bits", {}))
    pending[name] = claripy.BoolV(False)
    state.globals["pending_flag_bits"] = pending
    value = claripy.If(condition, claripy.ZeroExt(value.size() - 1, bit), value)
    setattr(state.regs, name, value)
    return value


def before_instruction(state, ins, policy):
    require_defined(state, BRANCH_FLAGS.get(ins.mnemonic, ()))
    context = {"undefined": dict(state.globals.get("undefined_flags", {}))}
    context["pending"] = dict(state.globals.get("pending_flag_bits", {}))
    if state.globals.get("unknown_flag_bits"):
        context["saved_flags"] = {n: getattr(state.regs, n) for n in STATUS | {"af"}}
    if ins.mnemonic == "adc":
        require_defined(state, {"cf"})
        context["carry"] = state.regs.cf
    if ins.mnemonic in {"add", "adc", "sub", "cmp", "neg", "inc", "dec"}:
        # Capture operands before pcode changes them. A memory operand's value
        # comes from its recorded architectural read below.
        context["arithmetic"] = [
            getattr(state.regs, ins.reg_name(op.reg))
            if op.type == capstone.x86.X86_OP_REG
            else claripy.BVV(op.imm & ((1 << (op.size * 8)) - 1), op.size * 8)
            if op.type == capstone.x86.X86_OP_IMM
            else None
            for op in ins.operands
        ]
    if ins.mnemonic in {"shl", "shr", "sar"}:
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
    if mnemonic in {"add", "adc", "sub", "cmp", "and", "or", "xor", "test", "neg"}:
        defines = STATUS
    elif mnemonic in {"inc", "dec"}:
        defines = STATUS - {"cf"}
    elif mnemonic in {"cld", "std"}:
        defines = {"df"}
    elif mnemonic == "mul":
        defines, invalidates = {"cf", "of"}, {"pf", "zf", "sf"}
    elif mnemonic in {"shl", "shr", "sar"}:
        count = context["count"]
        zero = count == 0
        for name in STATUS:
            old = undefined.get(name, claripy.BoolV(False))
            bad = claripy.BoolV(False)
            if name == "cf" and mnemonic != "sar":
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
    # AF becomes observable through PUSHF and interrupt frames in execution
    # analysis. Logical operations, MUL and nonzero shifts leave it undefined.
    if mnemonic in {"add", "adc", "sub", "cmp", "neg", "inc", "dec"}:
        operands = list(context["arithmetic"])
        reads = iter(e[5] for e in events if e[1] == "read")
        operands = [next(reads) if value is None else value for value in operands]
        left = operands[0]
        right = operands[1] if len(operands) > 1 else claripy.BVV(1, left.size())
        if mnemonic == "neg":
            left, right = claripy.BVV(0, left.size()), left
        result = left + right if mnemonic in {"add", "adc", "inc"} else left - right
        if mnemonic == "adc":
            result += claripy.ZeroExt(
                left.size() - context["carry"].size(), context["carry"]
            )
        # Pinned SLEIGH omits AF arithmetic. Intel's nibble carry/borrow rule
        # repairs the flag only; instruction execution remains in the lifter.
        state.regs.af = claripy.ZeroExt(
            state.regs.af.size() - 1, (left ^ right ^ result)[4]
        )
        defines = defines | {"af"}
    elif mnemonic in {"and", "or", "xor", "test", "mul"}:
        invalidates = invalidates | {"af"}
    elif mnemonic in {"shl", "shr", "sar"}:
        undefined["af"] = claripy.If(
            context["count"] == 0,
            undefined.get("af", claripy.BoolV(False)),
            claripy.BoolV(True),
        )
    for name in defines:
        undefined[name] = claripy.BoolV(False)
    for name in invalidates:
        undefined[name] = claripy.BoolV(True)
        if state.globals.get("unknown_flag_bits"):
            old = getattr(state.regs, name)
            setattr(state.regs, name, claripy.BVV(0, old.size()))
    if "saved_flags" in context and mnemonic in {"shl", "shr", "sar"}:
        for name, old in context["saved_flags"].items():
            current = getattr(state.regs, name)
            setattr(
                state.regs,
                name,
                claripy.If(
                    context["count"] == 0,
                    old,
                    claripy.If(
                        undefined.get(name, claripy.BoolV(False)),
                        claripy.BVV(0, current.size()),
                        current,
                    ),
                ),
            )
    pending = context["pending"].copy()
    for name in defines:
        pending[name] = claripy.BoolV(False)
    for name in invalidates:
        pending[name] = claripy.BoolV(True)
    if mnemonic in {"shl", "shr", "sar"}:
        for name in STATUS | {"af"}:
            pending[name] = claripy.If(
                context["count"] == 0,
                pending.get(name, context["undefined"].get(name, claripy.BoolV(False))),
                undefined.get(name, claripy.BoolV(False)),
            )
    state.globals["pending_flag_bits"] = pending
    state.globals["undefined_flags"] = undefined
