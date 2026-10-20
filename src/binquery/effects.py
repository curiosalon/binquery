"""Architectural RAM events for qualified single-destination p-code arithmetic.

SLEIGH reloads the old operand for carries and the newly stored operand for
flags. Normalize only after proving the expected load/store/load shape. Keep
computed values and execution constraints unchanged; no instruction emulation.
"""

import capstone

from .model import Unsupported

MEMORY_ARITHMETIC = {
    "add",
    "sub",
    "inc",
    "dec",
    "and",
    "or",
    "xor",
    "not",
    "shl",
    "shr",
}


def is_memory_arithmetic(ins):
    return (
        ins.mnemonic in MEMORY_ARITHMETIC
        and ins.operands
        and ins.operands[0].type == capstone.x86.X86_OP_MEM
    )


def normalize_arithmetic(state, ins, events):
    def reject():
        raise Unsupported("Unqualified real mode memory arithmetic effect shape")

    if (
        not is_memory_arithmetic(ins)
        or sum(o.type == capstone.x86.X86_OP_MEM for o in ins.operands) != 1
        or ins.operands[0].size not in (1, 2)
        or any(ins.prefix)
    ):
        reject()
    writes = [i for i, e in enumerate(events) if e[1] == "write"]
    if len(writes) != 1 or writes[0] == 0:
        reject()
    split = writes[0]
    read, write = events[0], events[split]
    size = ins.operands[0].size

    def equal(a, b):
        # Failure/timeout must propagate, never be interpreted as equality.
        return not state.solver.satisfiable(extra_constraints=[a != b])

    for i, event in enumerate(events):
        if (
            event[0] != read[0]
            or event[2] != ins.address
            or event[4] != size
            or event[1] != ("write" if i == split else "read")
            or not equal(event[3], read[3])
        ):
            reject()
        if i != split and not equal(event[5], (read if i < split else write)[5]):
            reject()
    return (read, write)
