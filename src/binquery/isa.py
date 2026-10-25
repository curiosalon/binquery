"""Conservative instruction forms; no privilege or implicit runtime state."""

import capstone

from .model import Unsupported

ALLOWED = set(
    "mov movabs movzx movsx lea add sub cmp inc dec and or xor push pop call ret jmp "
    "ja jae jb jbe je jne jg jge jl jle js jns jo jno jp jnp nop".split()
)
REAL_ADDITIONS = {
    "cld",
    "std",
    "test",
    "not",
    "neg",
    "mul",
    "shl",
    "shr",
    "adc",
    "sar",
    "xchg",
}
SEGMENTS = set("cs ds ss es fs gs".split())
GENERAL16 = set("ax bx cx dx si di bp sp al ah bl bh cl ch dl dh".split())
GENERAL64 = GENERAL16 | set(
    "rax rbx rcx rdx rsi rdi rbp rsp eax ebx ecx edx esi edi ebp esp sil dil bpl spl".split()
)
GENERAL64 |= {f"r{i}{suffix}" for i in range(8, 16) for suffix in ("", "d", "w", "b")}


def qualify(ins, real):
    if real:
        from .transfers import qualify_far

        if qualify_far(ins):
            return
    if ins.mnemonic not in ALLOWED | (REAL_ADDITIONS if real else set()):
        raise Unsupported(f"Instruction {ins.mnemonic} is not qualified")
    if ins.mnemonic == "xchg" and any(
        op.type != capstone.x86.X86_OP_REG for op in ins.operands
    ):
        raise Unsupported("Only register XCHG is qualified")
    if ins.mnemonic == "neg" and any(
        op.type != capstone.x86.X86_OP_REG for op in ins.operands
    ):
        raise Unsupported("NEG memory effects are not qualified")
    # REX is separate from legacy prefix[] and allowed in the AMD64 profile.
    if any(ins.prefix):
        # An ordinary real16 memory override selects the actual contract-owned
        # segment; operand/address size, repeat and lock prefixes stay excluded.
        overrides = {0x26: "es", 0x2E: "cs", 0x36: "ss", 0x3E: "ds"}
        selected = overrides.get(ins.prefix[1])
        memory = [op for op in ins.operands if op.type == capstone.x86.X86_OP_MEM]
        if not (
            real
            and selected
            and not any(ins.prefix[i] for i in (0, 2, 3))
            and (memory or ins.mnemonic == "cmp")
            and all(ins.reg_name(op.mem.segment) == selected for op in memory)
        ):
            raise Unsupported("Legacy instruction prefixes are not qualified")
    registers = (
        GENERAL16 | {"ip", "flags", "eflags", "cs", "ds", "ss", "es"}
        if real
        else GENERAL64 | {"rip", "rflags", "eflags"}
    )
    # Capstone reports implicit near CALL state as EIP/ESP even in mode 16.
    # Explicit 32 bit operands still fail the separate operand check below.
    implicit = registers | {"eip", "esp"} if real else registers
    reads, writes = ins.regs_access()
    for reg in set(reads) | set(writes):
        name = ins.reg_name(reg)
        if name not in implicit:
            raise Unsupported(f"Unmodeled register {name}")
    segment_writes = {ins.reg_name(reg) for reg in writes} & SEGMENTS
    if segment_writes and (
        not real
        or ins.mnemonic not in {"mov", "pop"}
        or not segment_writes <= {"ds", "es"}
    ):
        raise Unsupported("Only real mode MOV/POP updates to DS/ES are qualified")
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_REG:
            names = [ins.reg_name(op.reg)]
        elif op.type == capstone.x86.X86_OP_MEM:
            names = [
                ins.reg_name(r)
                for r in (op.mem.base, op.mem.index, op.mem.segment)
                if r
            ]
            if op.size not in (1, 2, 4, 8) or (real and op.size > 2):
                raise Unsupported("Memory operand width is not qualified")
        elif op.type == capstone.x86.X86_OP_IMM:
            names = []
        else:
            raise Unsupported("Operand form is not qualified")
        if any(name not in registers for name in names):
            raise Unsupported(f"Unmodeled operand registers {names}")
