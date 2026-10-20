"""Conservative instruction forms; no privilege or implicit runtime state."""

import capstone

from .model import Unsupported

ALLOWED = set(
    "mov movabs movzx movsx lea add sub cmp inc dec and or xor push pop call ret jmp "
    "ja jae jb jbe je jne jg jge jl jle js jns jo jno jp jnp nop".split()
)
REAL_ADDITIONS = {"cld", "std", "test", "not", "mul", "shl", "shr"}
SEGMENTS = set("cs ds ss es fs gs".split())
GENERAL16 = set("ax bx cx dx si di bp sp al ah bl bh cl ch dl dh".split())
GENERAL64 = GENERAL16 | set(
    "rax rbx rcx rdx rsi rdi rbp rsp eax ebx ecx edx esi edi ebp esp sil dil bpl spl".split()
)
GENERAL64 |= {f"r{i}{suffix}" for i in range(8, 16) for suffix in ("", "d", "w", "b")}


def qualify(ins, real):
    if ins.mnemonic not in ALLOWED | (REAL_ADDITIONS if real else set()):
        raise Unsupported(f"Instruction {ins.mnemonic} is not qualified")
    # REX is separate from legacy prefix[] and allowed in the AMD64 profile.
    if any(ins.prefix):
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
