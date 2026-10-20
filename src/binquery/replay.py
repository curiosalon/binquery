"""Independent concrete execution of materialized inputs, using Unicorn."""

from __future__ import annotations

import time
import unicorn
from unicorn import x86_const as x86

from .engine import FLAGS
from .model import Invalid, fields
from .isa import qualify


def validate_witness(analysis, witness):
    fields(
        witness,
        {"registers", "flags", "memory", "expected"},
        {"registers", "flags", "memory", "expected"},
    )
    names = analysis.register_names
    bits = 16 if analysis.real else 64

    def registers(values):
        fields(values, names, names)
        if any(type(v) is not int or not 0 <= v < 1 << bits for v in values.values()):
            raise Invalid("Witness register value exceeds its width")

    registers(witness["registers"])
    if type(witness["flags"]) is not int or witness["flags"] != analysis.spec["flags"]:
        raise Invalid("Witness flags differ from the contract")
    rows = witness["memory"]
    if not isinstance(rows, list) or len(rows) != len(analysis.input_memory):
        raise Invalid("Witness memory declarations differ from the contract")
    constraints = [analysis.input_regs[n] == v for n, v in witness["registers"].items()]
    for row, (address, expr) in zip(rows, analysis.input_memory):
        fields(row, {"address", "hex"}, {"address", "hex"})
        if (
            type(row["address"]) is not int
            or row["address"] != address
            or not isinstance(row["hex"], str)
        ):
            raise Invalid("Witness memory layout differs from the contract")
        try:
            raw = bytes.fromhex(row["hex"])
        except ValueError as exc:
            raise Invalid("Invalid witness memory hex") from exc
        if len(raw) * 8 != expr.size():
            raise Invalid("Witness memory extent differs from the contract")
        constraints.append(expr == int.from_bytes(raw, "big"))
    if not analysis.initial.solver.satisfiable(extra_constraints=constraints):
        raise Invalid("Witness inputs are outside the declared initial domain")
    expected = witness["expected"]
    fields(
        expected,
        {"registers", "stop", "path", "events", "flags", "memory"},
        {"registers", "stop", "path", "events"},
    )
    registers(expected["registers"])
    if type(expected["stop"]) is not int or expected["stop"] not in analysis.stop_map:
        raise Invalid("Witness stop is not declared")
    path = expected["path"]
    if (
        not isinstance(path, list)
        or not 0 < len(path) <= analysis.spec["limits"]["steps"]
        or path[0] != analysis.spec["entry"]
        or any(type(a) is not int or a not in analysis.instructions for a in path)
    ):
        raise Invalid("Invalid witness instruction path")
    for address in path:
        qualify(analysis.instructions[address], analysis.real)
    flags = expected.get("flags", {})
    fields(flags, FLAGS)
    if any(type(v) is not int or v not in (0, 1) for v in flags.values()):
        raise Invalid("Invalid witness output flags")
    events = expected["events"]
    if not isinstance(events, list) or len(events) > 16 * len(path):
        raise Invalid("Invalid witness memory events")
    for e in events:
        keys = {"step", "kind", "instruction", "address", "size", "value"}
        fields(e, keys, keys)
        if (
            any(type(e[k]) is not int for k in keys - {"kind"})
            or e["kind"] not in ("read", "write")
            or not 1 <= e["step"] <= len(path)
            or e["instruction"] != path[e["step"] - 1]
            or e["size"] not in (1, 2, 4, 8)
            or not 0 <= e["address"] < (0x110000 if analysis.real else 1 << 47)
            or not 0 <= e["value"] < 1 << (8 * e["size"])
        ):
            raise Invalid("Invalid witness memory event")
    final = expected.get("memory", [])
    if not isinstance(final, list):
        raise Invalid("Expected final memory must be a list")
    from .observations import regions, validate_observations

    observations = []
    for row in final:
        fields(row, {"name", "address", "hex"}, {"name", "address", "hex"})
        if type(row["address"]) is not int or not isinstance(row["hex"], str):
            raise Invalid("Invalid final memory witness")
        try:
            raw = bytes.fromhex(row["hex"])
        except ValueError as exc:
            raise Invalid("Invalid final memory witness hex") from exc
        observations.append(
            {
                "name": row["name"],
                "left": row["address"],
                "right": row["address"],
                "size": len(raw),
            }
        )
    validate_observations(
        analysis, regions(observations, "witness final memory"), "left"
    )


def replay(analysis, witness):
    begin = time.monotonic()
    validate_witness(analysis, witness)
    u = unicorn.Uc(
        unicorn.UC_ARCH_X86, unicorn.UC_MODE_16 if analysis.real else unicorn.UC_MODE_64
    )
    pages = set()
    spans = [(a, len(raw)) for a, raw in analysis.chunks]
    spans += [(r["address"], len(bytes.fromhex(r["hex"]))) for r in witness["memory"]]
    spans += [(a, 1) for a in analysis.stop_map]
    # Include saved frame writes and every expected memory access. This maps
    # storage, not invented initial values; first read checking below detects
    # undeclared native inputs before accepting replay.
    spans += [(e["address"], e["size"]) for e in witness["expected"]["events"]]
    for address, size in spans:
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            pages.add(page)
    for page in sorted(pages):
        u.mem_map(page, 4096)
    initialized = set()
    for address, raw in analysis.chunks:
        u.mem_write(address, raw)
        initialized.update(range(address, address + len(raw)))
    for row in witness["memory"]:
        raw = bytes.fromhex(row["hex"])
        u.mem_write(row["address"], raw)
        initialized.update(range(row["address"], row["address"] + len(raw)))
    for name, value in witness["registers"].items():
        u.reg_write(getattr(x86, "UC_X86_REG_" + name.upper()), value)
    u.reg_write(x86.UC_X86_REG_EFLAGS, witness["flags"])
    path, events, errors, stop = [], [], [], []

    def code_hook(uc, address, size, _):
        if address in analysis.stop_map:
            stop.append(address)
            uc.emu_stop()
        elif address not in analysis.instructions:
            errors.append(f"Native target outside declared code: {address:#x}")
            uc.emu_stop()
        else:
            ins = analysis.instructions[address]
            if (
                analysis.real
                and ins.mnemonic in {"shl", "shr"}
                and analysis.spec.get("shift_count", "portable") == "portable"
            ):
                import capstone

                operand = ins.operands[1]
                raw_count = (
                    operand.imm
                    if operand.type == capstone.x86.X86_OP_IMM
                    else uc.reg_read(x86.UC_X86_REG_CL)
                )
                if raw_count > 31:
                    errors.append("Native shift count exceeds the portable model")
                    uc.emu_stop()
                    return
            path.append(address)

    def memory_hook(uc, access, address, size, value, _):
        kind = "write" if access == unicorn.UC_MEM_WRITE else "read"
        if not path:
            errors.append("Native access before instruction")
            uc.emu_stop()
            return
        if kind == "read":
            if any(a not in initialized for a in range(address, address + size)):
                errors.append(f"Native read of undeclared initial memory: {address:#x}")
                uc.emu_stop()
            value = int.from_bytes(uc.mem_read(address, size), "little")
        else:
            if any(
                address < start + len(raw) and start < address + size
                for start, raw in analysis.chunks
            ):
                errors.append("Native write to selected code")
                uc.emu_stop()
            initialized.update(range(address, address + size))
            value &= (1 << (8 * size)) - 1
        events.append(
            {
                "step": len(path),
                "kind": kind,
                "instruction": path[-1],
                "address": address,
                "size": size,
                "value": value,
            }
        )

    u.hook_add(unicorn.UC_HOOK_CODE, code_hook)
    u.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, memory_hook)
    try:
        u.emu_start(
            analysis.spec["entry"],
            0,
            timeout=analysis.spec["limits"]["seconds"] * 1000000,
            count=analysis.spec["limits"]["steps"] + 1,
        )
    except unicorn.UcError as exc:
        errors.append(str(exc))
    outputs = {
        name: u.reg_read(getattr(x86, "UC_X86_REG_" + name.upper()))
        for name in analysis.register_names
    }
    expected = witness["expected"]
    if stop != [expected["stop"]]:
        errors.append("Stop differs or native execution incomplete")
    if path != expected["path"]:
        errors.append("Instruction path differs")
    if outputs != expected["registers"]:
        errors.append("Register outputs differ")
    if events != expected["events"]:
        errors.append("Ordered memory effects differ")
    flag_value = u.reg_read(x86.UC_X86_REG_EFLAGS)
    flags = {name: (flag_value >> bit) & 1 for name, bit in FLAGS.items()}
    for name, value in expected.get("flags", {}).items():
        if flags[name] != value:
            errors.append("Observable flag differs: " + name)
    final_memory = []
    for row in expected.get("memory", []):
        size = len(bytes.fromhex(row["hex"]))
        address = row["address"]
        if not set(range(address, address + size)) <= initialized:
            errors.append("Native final memory includes uninitialized bytes")
            continue
        try:
            actual = bytes(u.mem_read(address, size)).hex()
        except unicorn.UcError as exc:
            errors.append("Native final memory unavailable: " + str(exc))
            continue
        final_memory.append({"name": row["name"], "address": address, "hex": actual})
        if actual != bytes.fromhex(row["hex"]).hex():
            errors.append("Final memory differs: " + row["name"])
    return {
        "matched": not errors,
        "errors": errors,
        "stop": stop,
        "registers": outputs,
        "flags": flags,
        "path": path,
        "events": events,
        "final_memory": final_memory,
        "elapsed_seconds": time.monotonic() - begin,
    }
