"""Property queries and paired comparisons of declared outputs."""

import time

from angr import claripy

from .engine import Analysis, FLAGS, concrete
from .model import Invalid, Unsupported
from .replay import replay


def targets(binary, spec, site, maximum=32):
    """Observe one qualified indirect transfer without entering its destinations."""
    import capstone
    from .model import Incomplete

    analysis = Analysis(binary, spec)
    ins = analysis.instructions.get(site)
    if ins is None or not (
        ins.mnemonic in ("ljmp", "lcall", "retf")
        and analysis.real
        or ins.mnemonic in ("jmp", "call")
        and len(ins.operands) == 1
        and ins.operands[0].type in (capstone.x86.X86_OP_REG, capstone.x86.X86_OP_MEM)
    ):
        raise Unsupported("Targets needs a decoded qualified control transfer")
    if not 1 <= maximum <= 256:
        raise Invalid("Target limit must be between 1 and 256")
    analysis.target_site = site
    analysis.explore()
    rows = {}
    domain_complete = True
    for state, expression in analysis.target_states:
        remaining = state.copy()
        far = (
            state.globals.get("far_target")
            if ins.mnemonic in ("ljmp", "lcall", "retf")
            else None
        )
        identity = claripy.Concat(*far) if far else expression
        # Enumerate the residual domain, including predecessor constraints.
        # Every model is excluded explicitly; only UNSAT establishes exhaustion.
        while remaining.solver.satisfiable():
            if time.monotonic() - analysis.started > spec["limits"]["seconds"]:
                analysis.issues.append(
                    dict(kind="INCONCLUSIVE", reason="Target enumeration time limit")
                )
                domain_complete = False
                break
            value = remaining.solver.eval(identity)
            if value not in rows and len(rows) >= maximum:
                domain_complete = False
                break
            selected = remaining.copy()
            selected.add_constraints(identity == value)
            selected.regs.ip = expression
            witness = analysis.witness(selected)
            witness["expected"]["transfer"] = site
            native = replay(analysis, witness)
            if value not in rows:
                physical = selected.solver.eval(expression)
                interior = any(
                    a < physical < a + i.size for a, i in analysis.instructions.items()
                )
                row = dict(
                    address=dict(
                        space="physical" if analysis.real else "virtual",
                        offset=physical,
                    ),
                    kind="far" if far else "near",
                    width=32 if far else 16 if analysis.real else 64,
                    destination="instruction_boundary"
                    if physical in analysis.instructions
                    else "interior_instruction"
                    if interior
                    else "outside_supplied_code",
                    witness=witness,
                    replay=native,
                )
                if analysis.real:
                    cs = concrete(selected, selected.regs.cs)
                    row.update(
                        segment=cs,
                        offset=selected.solver.eval(far[1])
                        if far
                        else physical - (cs << 4),
                    )
                rows[value] = row
            if not native["matched"]:
                analysis.issues.append(
                    dict(
                        kind="INCONCLUSIVE",
                        reason="Target witness replay differs",
                        target=value,
                    )
                )
            remaining.add_constraints(identity != value)
        if not domain_complete:
            break
    complete = not analysis.issues and domain_complete
    status = (
        "COMPLETE"
        if complete and rows
        else "UNREACHABLE_WITHIN_SCOPE"
        if complete
        else "INCOMPLETE"
    )
    return analysis.summary() | dict(
        operation="targets",
        status=status,
        complete=complete,
        site=dict(space="physical" if analysis.real else "virtual", offset=site),
        targets=[rows[n] for n in sorted(rows)],
        predecessor_states=len(analysis.target_states),
        target_limit=maximum,
        domain_exhausted=domain_complete,
        conflicts=[
            dict(address=r["address"], reason=r["destination"])
            for r in rows.values()
            if r["destination"] != "instruction_boundary"
        ],
        native_import_qualified=False,
        assumptions=dict(
            registers=spec["registers"],
            memory=spec["memory"],
            entry=spec["entry"],
            stops=spec["stops"],
        ),
        scope="Declared initial state and executed prefixes only; supplied bytes are initial contents, not an invariant. Outside-supplied-code targets remain observations, not inferred valid bodies; mutable writers and overlay correspondence require separate evidence.",
    )


def query(binary, spec):
    analysis = Analysis(binary, spec).explore()
    answers = []
    for claim in spec["claims"]:
        row = {
            "claim": claim,
            "status": "INCONCLUSIVE",
            "scope": "declared initial state and stops",
        }
        eligible = 0
        reached = False
        for state in analysis.leaves:
            kind = claim["kind"]
            if (
                kind == "return_equals"
                and analysis.stop_map[concrete(state, state.regs.ip)] != "return"
            ):
                continue
            eligible += 1
            if kind == "preserved":
                violation = analysis.read_register(
                    state, claim["register"]
                ) != analysis.read_register(analysis.initial, claim["register"])
            elif kind == "return_equals":
                violation = (
                    analysis.read_register(state, claim["register"]) != claim["value"]
                )
            else:
                accessed = any(
                    e[1] == "read" and e[2] == claim["instruction"]
                    for e in state.globals["events"]
                )
                reached |= claim["instruction"] in state.globals["path"]
                violation = claripy.BoolV(accessed)
            if state.solver.satisfiable(extra_constraints=[violation]):
                witness = analysis.witness(state, [violation])
                if analysis.real and claim.get("register") in FLAGS:
                    selected = state.copy()
                    selected.add_constraints(violation)
                    _pin(selected, analysis, witness)
                    witness["expected"]["flags"] = {
                        claim["register"]: selected.solver.eval(
                            analysis.read_register(selected, claim["register"])
                        )
                    }
                native = replay(analysis, witness)
                row.update(
                    status="REFUTED" if native["matched"] else "INCONCLUSIVE",
                    witness=witness,
                    replay=native,
                )
                if not native["matched"]:
                    row["reason"] = (
                        "Symbolic witness did not agree with independent replay"
                    )
                break
        else:
            if not analysis.issues and eligible:
                row["status"] = "ESTABLISHED_WITHIN_MODEL"
            else:
                row["reason"] = "Incomplete exploration or no eligible terminal paths"
        row["eligible_terminal_paths"] = eligible
        if claim["kind"] == "no_read":
            row["instruction_reached_on_examined_paths"] = reached
        if claim["kind"] == "return_equals":
            row["scope"] = "normal return stops only, under declared initial state"
        answers.append(row)
    if not answers:
        raise Invalid("At least one claim is required")
    return analysis.summary() | {"operation": "query", "claims": answers}


def _pin(state, analysis, witness):
    for name, value in witness["registers"].items():
        state.add_constraints(analysis.input_regs[name] == value)
    for (address, expr), row in zip(analysis.input_memory, witness["memory"]):
        assert address == row["address"]
        state.add_constraints(expr == int.from_bytes(bytes.fromhex(row["hex"]), "big"))


def _effect_difference(a, b):
    differences = [claripy.BoolV(len(a) != len(b))]
    for x, y in zip(a, b):
        shape = x[1] != y[1] or x[4] != y[4]
        differences.append(claripy.BoolV(shape))
        if not shape:
            differences.extend([x[3] != y[3], x[5] != y[5]])
    return claripy.Or(*differences)


def _native_difference(kind, left, right, lr, rr, observe, pointers, relation):
    if kind == "exit_kind":
        return left.stop_map.get(
            lr["stop"][0] if lr["stop"] else -1
        ) != right.stop_map.get(rr["stop"][0] if rr["stop"] else -1)
    if kind == "registers":
        return any(
            (lr["flags"] if n in FLAGS else lr["registers"])[n]
            != (rr["flags"] if n in FLAGS else rr["registers"])[n]
            for n in observe
        )
    if kind == "pointers":
        offsets = [
            (
                relation.native_pointer(p, "left", lr),
                relation.native_pointer(p, "right", rr),
            )
            for p in pointers
        ]
        return all(a is not None and b is not None for a, b in offsets) and any(
            a != b for a, b in offsets
        )
    if kind == "final_memory":
        return [r["hex"] for r in lr["final_memory"]] != [
            r["hex"] for r in rr["final_memory"]
        ]

    def external(rows):
        return [(e["kind"], e["address"], e["size"], e["value"]) for e in rows]

    return external(lr["events"]) != external(rr["events"])


def _pair_witness(left, right, a, b, joint, violation, observe, memory):
    from .observations import materialize_memory

    chosen = joint.copy()
    chosen.add_constraints(violation)
    lw = left.witness(chosen)
    _pin(chosen, left, lw)
    selected_right = b.copy()
    selected_right.add_constraints(*chosen.solver.constraints)
    rw = right.witness(selected_right)
    _pin(selected_right, right, rw)
    _pin(chosen, right, rw)
    for side, analysis, state, witness in [
        ("left", left, chosen, lw),
        ("right", right, selected_right, rw),
    ]:
        witness["expected"]["flags"] = {
            n: state.solver.eval(analysis.read_register(state, n))
            for n in observe
            if n in FLAGS and analysis.real
        }
        witness["expected"]["memory"] = materialize_memory(
            analysis, state, memory, side
        )
    return lw, rw, replay(left, lw), replay(right, rw)


def compare(
    left_path,
    right_path,
    left_spec,
    right_spec,
    observe,
    effects=False,
    comparison=None,
):
    from .observations import (
        comparison_contract,
        validate_observations,
        final_bytes,
        omitted_writes,
    )
    from .relation import Relation

    begin = time.monotonic()
    config = comparison_contract(comparison or {"schema": 1})
    memory, pointers = config["memory"], config["pointers"]
    if not observe and not effects and not memory and not pointers:
        raise Invalid(
            "Declare registers, final RAM, near pointers or ordered memory effects"
        )
    relational = "relation" in config
    if not relational:
        for key in (
            "architecture",
            "registers",
            "flags",
            "memory",
            "a20",
            "shift_count",
        ):
            if left_spec.get(key) != right_spec.get(key):
                raise Unsupported(
                    "Pair proof requires identical input declarations or an explicit relation: "
                    + key
                )
    left = Analysis(left_path, left_spec, namespace="left_" if relational else "")
    right = Analysis(right_path, right_spec, namespace="right_" if relational else "")
    if left.project.arch.name != right.project.arch.name:
        raise Unsupported("Cross-architecture equivalence is not qualified")
    relation = Relation(left, right, config["relation"]) if relational else None
    if relation:
        relation.validate_memory(memory)
        for p in pointers:
            if p["region"] not in relation.regions:
                raise Invalid("Pointer observable names an unknown region")
    for name in observe:
        left.read_register(left.initial, name)
        right.read_register(right.initial, name)
    validate_observations(left, memory, "left")
    validate_observations(right, memory, "right")
    left.explore()
    right.explore()
    kinds = (
        ["exit_kind"]
        + (["registers"] if observe else [])
        + (["pointers"] if pointers else [])
    )
    kinds += (["final_memory"] if memory else []) + (
        ["ordered_memory_effects"] if effects else []
    )
    results = {k: {"status": "INCONCLUSIVE"} for k in kinds}
    report = {
        "operation": "compare",
        "status": "INCONCLUSIVE",
        "left": left.summary(),
        "right": right.summary(),
        "observables": {
            "registers": observe,
            "final_memory": memory,
            "pointers": pointers,
            "ordered_memory_effects": effects,
            "ordered_effect_addresses": "raw physical/virtual",
            "exit_kind": True,
        },
        "scope": "Declared observables only under the explicit input relation; omitted state is unproved",
        "unobserved_state": {
            "memory": "All bytes outside the selected final regions; include relevant neighbors and aliases",
            "registers": sorted(
                set(left.register_names)
                - set(observe)
                - {p["register"] for p in pointers}
            ),
            "flags": sorted(set(FLAGS) - set(observe)),
            "ordered_accesses": not effects,
        },
        "writes_outside_final_memory": {
            "left": omitted_writes(left, memory, "left"),
            "right": omitted_writes(right, memory, "right"),
        },
        "byte_match": [raw for _, raw in left.chunks]
        == [raw for _, raw in right.chunks],
        "input_relation": relation.summary()
        if relation
        else "identical named registers and declared memory bytes; no relocation mapping",
        "comparisons": results,
    }
    # Read observations without adding execution memory events. Unknown final
    # bytes fail even when there is no feasible pair on another path.
    final = {
        side: [final_bytes(analysis, state, memory, side) for state in analysis.leaves]
        for side, analysis in (("left", left), ("right", right))
    }
    pointer_values = {
        side: [
            [relation.pointer_offset(analysis, state, p, side) for p in pointers]
            for state in analysis.leaves
        ]
        for side, analysis in (("left", left), ("right", right))
    }
    pairs = 0
    timed_out = False
    for ai, a in enumerate(left.leaves):
        for bi, b in enumerate(right.leaves):
            if (
                time.monotonic() - begin
                > left_spec["limits"]["seconds"] + right_spec["limits"]["seconds"]
            ):
                timed_out = True
                break
            joint = a.copy()
            joint.add_constraints(*b.solver.constraints)
            if not joint.solver.satisfiable():
                continue
            pairs += 1
            violations = {
                "exit_kind": claripy.BoolV(
                    left.stop_map[concrete(a, a.regs.ip)]
                    != right.stop_map[concrete(b, b.regs.ip)]
                )
            }
            if observe:
                violations["registers"] = claripy.Or(
                    *[
                        left.read_register(a, n) != right.read_register(b, n)
                        for n in observe
                    ]
                )
            if pointers:
                violations["pointers"] = claripy.Or(
                    *[
                        x != y
                        for x, y in zip(
                            pointer_values["left"][ai], pointer_values["right"][bi]
                        )
                    ]
                )
            if memory:
                violations["final_memory"] = claripy.Or(
                    *[x != y for x, y in zip(final["left"][ai], final["right"][bi])]
                )
            if effects:
                violations["ordered_memory_effects"] = _effect_difference(
                    a.globals["events"], b.globals["events"]
                )
            for kind, violation in violations.items():
                result = results[kind]
                if result.get("witness") or not joint.solver.satisfiable(
                    extra_constraints=[violation]
                ):
                    continue
                lw, rw, lr, rr = _pair_witness(
                    left, right, a, b, joint, violation, observe, memory
                )
                ok = (
                    lr["matched"]
                    and rr["matched"]
                    and _native_difference(
                        kind, left, right, lr, rr, observe, pointers, relation
                    )
                )
                result.update(
                    status="DIFFERENT" if ok else "INCONCLUSIVE",
                    witness={"left": lw, "right": rw},
                    replay={"left": lr, "right": rr},
                )
                if not ok:
                    result["reason"] = (
                        "Symbolic difference not confirmed by independent replay"
                    )
                if kind == "final_memory" and ok:
                    result["differing_bytes"] = [
                        {
                            "name": r["name"],
                            "offset": i,
                            "left_address": r["left"] + i,
                            "right_address": r["right"] + i,
                            "left": x,
                            "right": y,
                        }
                        for r, lm, rm in zip(
                            memory, lr["final_memory"], rr["final_memory"]
                        )
                        for i, (x, y) in enumerate(
                            zip(bytes.fromhex(lm["hex"]), bytes.fromhex(rm["hex"]))
                        )
                        if x != y
                    ]
        if timed_out:
            break
    complete = (
        not timed_out
        and not left.issues
        and not right.issues
        and bool(left.leaves and right.leaves and pairs)
    )
    for result in results.values():
        if not result.get("witness"):
            result["status"] = "EQUIVALENT_WITHIN_MODEL" if complete else "INCONCLUSIVE"
    differences = [r for r in results.values() if r["status"] == "DIFFERENT"]
    if differences:
        report.update(
            status="DIFFERENT",
            witness=differences[0]["witness"],
            replay=differences[0]["replay"],
        )
    elif all(r["status"] == "EQUIVALENT_WITHIN_MODEL" for r in results.values()):
        report["status"] = "EQUIVALENT_WITHIN_MODEL"
    else:
        report["reason"] = "Incomplete exploration, pairing, or independent replay"
    report.update(pairs_examined=pairs, elapsed_seconds=time.monotonic() - begin)
    return report
