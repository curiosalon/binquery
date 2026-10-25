"""Independent concrete witnesses, including current code bytes and native I/O."""

import time

import unicorn
import z3
from unicorn import x86_const as x86


def replay_witness(engine, witness):
    from .engine import FLAGS

    flag_bits = FLAGS | {"af": 4}
    unknowns = witness.get("unknown_flags", {})
    solver = z3.Solver()
    native_model = None
    if unknowns:
        solver.from_string(witness["smt2"])

    def resolved(value):
        nonlocal native_model
        if isinstance(value, dict):
            if "symbol" in value and "bits" in value:
                if native_model is None:
                    if solver.check() != z3.sat:
                        raise ValueError(
                            "Native undefined-bit observations contradict witness"
                        )
                    native_model = solver.model()
                return native_model.eval(
                    z3.BitVec(value["symbol"], value["bits"]), model_completion=True
                ).as_long()
            return {k: resolved(v) for k, v in value.items()}
        if isinstance(value, list):
            return [resolved(v) for v in value]
        return value

    start = time.monotonic()
    u = unicorn.Uc(
        unicorn.UC_ARCH_X86, unicorn.UC_MODE_16 if engine.real else unicorn.UC_MODE_64
    )
    pages = set()
    for mapping in engine.entry["mappings"]:
        lo, hi = mapping["address"], mapping["address"] + mapping["size"]
        pages.update(range(lo & ~4095, (hi + 4095) & ~4095, 4096))
    pages.update(row["target"] & ~4095 for row in witness["trace"])
    # Unicorn may decode ahead across a page after the last instruction.
    # These guard pages are never admitted data or execution: the boundary
    # hook stops before another instruction and memory permissions still apply.
    pages.update((row["target"] & ~4095) + 4096 for row in witness["trace"])
    for page in sorted(pages):
        u.mem_map(page, 4096)
    for at, raw in engine.chunks:
        u.mem_write(at, raw)
    for row in witness["memory"]:
        u.mem_write(row["address"], bytes.fromhex(row["hex"]))
    for name, value in witness["registers"].items():
        u.reg_write(getattr(x86, "UC_X86_REG_" + name.upper()), value)
    u.reg_write(x86.UC_X86_REG_EFLAGS, witness["flags"])
    events, io, errors, path, frame_reads = [], [], [], [], []
    step = 0
    site = 0

    def memory(uc, access, at, size, value, _):
        mode = "write" if access == unicorn.UC_MEM_WRITE else "read"
        if not engine.permitted(at, size, "w" if mode == "write" else "r"):
            errors.append(f"Native {mode} outside permitted mapping at {at:#x}")
            uc.emu_stop()
        if mode == "read":
            value = int.from_bytes(uc.mem_read(at, size), "little")
        events.append(
            {
                "step": step,
                "kind": mode,
                "instruction": site,
                "address": at,
                "size": size,
                "value": value & ((1 << size * 8) - 1),
            }
        )

    def inp(uc, port, size, _):
        n = len(io)
        if n >= len(witness["io"]) or (
            witness["io"][n]["kind"],
            witness["io"][n]["port"],
            witness["io"][n]["size"],
        ) != ("port-in", port, size):
            errors.append("Native port read differs")
            uc.emu_stop()
            return 0
        value = witness["io"][n]["value"]
        io.append(
            {
                "step": step,
                "kind": "port-in",
                "instruction": site,
                "port": port,
                "size": size,
                "value": value,
            }
        )
        return value

    def out(uc, port, size, value, _):
        io.append(
            {
                "step": step,
                "kind": "port-out",
                "instruction": site,
                "port": port,
                "size": size,
                "value": value,
            }
        )

    def interrupt(uc, vector, _):
        if not engine.real or vector not in engine.config["interrupts"]:
            errors.append(f"Native unknown interrupt {vector}")
            uc.emu_stop()
            return
        # Unicorn reports INT rather than emulating a real-mode interrupt
        # controller. Deliver its architectural frame using native registers.
        ss = uc.reg_read(x86.UC_X86_REG_SS)
        sp = uc.reg_read(x86.UC_X86_REG_SP)
        flags = uc.reg_read(x86.UC_X86_REG_EFLAGS)
        for value in (
            flags,
            uc.reg_read(x86.UC_X86_REG_CS),
            uc.reg_read(x86.UC_X86_REG_IP),
        ):
            sp = (sp - 2) & 65535
            at = ss * 16 + sp
            memory(uc, unicorn.UC_MEM_WRITE, at, 2, value, None)
            uc.mem_write(at, (value & 65535).to_bytes(2, "little"))
        uc.reg_write(x86.UC_X86_REG_SP, sp)
        # Match architectural frame effects; the vector is RAM, not a stub.
        memory(uc, unicorn.UC_MEM_READ, vector * 4 + 2, 2, 0, None)
        memory(uc, unicorn.UC_MEM_READ, vector * 4, 2, 0, None)
        offset, segment = (
            int.from_bytes(uc.mem_read(vector * 4 + n, 2), "little") for n in (0, 2)
        )
        uc.reg_write(x86.UC_X86_REG_CS, segment)
        uc.reg_write(x86.UC_X86_REG_IP, offset)
        uc.reg_write(x86.UC_X86_REG_EFLAGS, flags & ~0x300)

    heads = 0
    event_start = 0
    io_start = 0
    row = None
    attempts = []

    def boundary(uc, address, size, _):
        nonlocal heads
        heads += 1
        if heads == 1:
            if address != site:
                errors.append("Native instruction address differs")
                uc.emu_stop()
            return
        # Unicorn may restart a TB before a code-page store commits. Its
        # pre-write hook then describes an abandoned attempt, not an effect.
        if heads <= 3 and address == site and row["target"] != site:
            now = {
                n: uc.reg_read(getattr(x86, "UC_X86_REG_" + n.upper()))
                for n in engine.register_names
            }
            if now == resolved(row["before"]):
                attempts.append(events[event_start:].copy())
                del events[event_start:]
                del io[io_start:]
                return
        uc.emu_stop()

    u.hook_add(unicorn.UC_HOOK_CODE, boundary)
    read_hook = u.hook_add(unicorn.UC_HOOK_MEM_READ, memory)
    u.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory)
    if engine.real:
        u.hook_add(unicorn.UC_HOOK_INSN, inp, None, 1, 0, x86.UC_X86_INS_IN)
        u.hook_add(unicorn.UC_HOOK_INSN, out, None, 1, 0, x86.UC_X86_INS_OUT)
        u.hook_add(unicorn.UC_HOOK_INTR, interrupt)
    try:
        for step, row in enumerate(witness["trace"], 1):
            site = row["instruction"]
            if not engine.permitted(site, len(bytes.fromhex(row["bytes"])), "x"):
                errors.append("Native execution outside executable mapping")
                break
            if (
                bytes(u.mem_read(site, len(bytes.fromhex(row["bytes"])))).hex()
                != row["bytes"]
            ):
                errors.append("Executed instruction bytes differ")
                break
            before = {
                n: u.reg_read(getattr(x86, "UC_X86_REG_" + n.upper()))
                for n in engine.register_names
            }
            native_flags = u.reg_read(x86.UC_X86_REG_EFLAGS)
            for symbol, origin in unknowns.items():
                if origin["step"] == step:
                    solver.add(
                        z3.BitVec(symbol, 1)
                        == ((native_flags >> flag_bits[origin["flag"]]) & 1)
                    )
                    native_model = None
            if any(
                (native_flags >> flag_bits[n]) & 1 != v
                for n, v in row.get("before_flags", {}).items()
            ):
                errors.append(f"Native flag inputs differ at step {step}")
                break
            if before != resolved(row["before"]):
                errors.append(f"Register inputs differ at step {step}")
                break
            path.append(site)
            u.ctl_remove_cache(site, site + 15)
            heads = 0
            attempts = []
            event_start, io_start = len(events), len(io)
            # Unicorn invalidates translated pages even when the write is
            # to nonexecutable data sharing that page with executable code.
            code_store = any(
                e["step"] == step
                and e["kind"] == "write"
                and any(
                    (m["address"] & ~4095) < ((e["address"] + e["size"] + 4095) & ~4095)
                    and (e["address"] & ~4095)
                    < ((m["address"] + m["size"] + 4095) & ~4095)
                    and "x" in m["permissions"]
                    for m in engine.entry["mappings"]
                )
                for e in witness["expected"]["events"]
            )
            frame_words = (
                (3 if row["mnemonic"] == "iret" else 2)
                if engine.real and row["mnemonic"] in {"retf", "iret"}
                else 0
            )
            if frame_words:
                # Unicorn 2.1.4's pre-read hook corrupts the RETF destination.
                # Observe the actual frame, then let the CPU execute the real
                # return without that hook. No target or state is supplied.
                u.hook_del(read_hook)
                for word in range(frame_words):
                    at = before["ss"] * 16 + ((before["sp"] + word * 2) & 65535)
                    memory(u, unicorn.UC_MEM_READ, at, 2, 0, None)
                frame_reads.append(step)
            try:
                u.emu_start(
                    site,
                    0,
                    count=4 if code_store else 1,
                    timeout=engine.spec["limits"]["seconds"] * 1000000,
                )
            finally:
                if frame_words:
                    read_hook = u.hook_add(unicorn.UC_HOOK_MEM_READ, memory)
            # QEMU's code-store restart can notify either before or after
            # retry. Count the completed instruction's effects once, accepting
            # only identical attempt logs (or an empty deferred retry).
            if attempts:
                attempts.append(events[event_start:].copy())
                nonempty = [a for a in attempts if a]
                if nonempty and any(a != nonempty[0] for a in nonempty):
                    errors.append("Native translation retry effects disagree")
                elif nonempty:
                    events[event_start:] = nonempty[0]
            after = {
                n: u.reg_read(getattr(x86, "UC_X86_REG_" + n.upper()))
                for n in engine.register_names
            }
            target = (
                u.reg_read(x86.UC_X86_REG_CS) * 16 + u.reg_read(x86.UC_X86_REG_IP)
                if engine.real
                else u.reg_read(x86.UC_X86_REG_RIP)
            )
            native_flags = u.reg_read(x86.UC_X86_REG_EFLAGS)
            if any(
                (native_flags >> flag_bits[n]) & 1 != v
                for n, v in row.get("after_flags", {}).items()
            ):
                errors.append(f"Native flag outputs differ at step {step}")
                break
            if target != row["target"] or after != resolved(row["after"]):
                errors.append(f"Native state/transfer differs at step {step}")
                break
    except (unicorn.UcError, ValueError) as exc:
        errors.append(str(exc))
    if events != resolved(witness["expected"]["events"]):
        errors.append("Ordered memory effects differ")
    if io != witness["io"]:
        errors.append("Port effects differ")
    return {
        "matched": not errors,
        "errors": errors,
        "instructions": len(path),
        "events": len(events),
        "elapsed_seconds": time.monotonic() - start,
        "return_frame_snapshots": frame_reads,
    }
