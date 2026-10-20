"""Explicit, total bounded input correspondence for fixed-segment real mode.

RAM rows correspond byte for byte. Only declared near register pointers are
translated. No inferred bindings, code rewriting, embedded pointer translation,
stack relocation, or general pointer equivalence.
"""

from angr import claripy

from .model import Invalid, Unsupported


def overlaps(a, size, b, length):
    return a < b + length and b < a + size


class Relation:
    def __init__(self, left, right, spec):
        self.analyses = {"left": left, "right": right}
        self.spec = spec
        self.regions = {r["name"]: r for r in spec["regions"]}
        if not left.real or not right.real:
            raise Unsupported(
                "Layout relations currently require the real16 profile on both sides"
            )
        for key in ("architecture", "flags", "a20", "shift_count"):
            if left.spec.get(key) != right.spec.get(key):
                raise Unsupported(
                    "Layout relation requires equal machine profiles and flags: " + key
                )
        pointer_names = {p["register"] for p in spec["pointers"]}
        for name in left.register_names:
            if name not in pointer_names and left.spec["registers"].get(
                name
            ) != right.spec["registers"].get(name):
                raise Unsupported(
                    "Only declared near input pointers may change register bindings: "
                    + name
                )
        ss_base = left.spec["registers"]["ss"] << 4
        window = spec.get("stack", {"address": ss_base, "size": 65536})
        self.stack, self.stack_size = window["address"], window["size"]
        sp = ss_base + left.spec["registers"]["sp"]
        if not ss_base <= self.stack < self.stack + self.stack_size <= ss_base + 65536:
            raise Unsupported("Stack window must lie inside the fixed SS segment")
        if not self.stack <= sp <= self.stack + self.stack_size:
            raise Unsupported("Initial SP is outside the fixed stack window")
        constraints = []
        for side, analysis in self.analyses.items():
            inputs = {
                a: (expr, row)
                for (a, expr), row in zip(
                    analysis.input_memory, analysis.spec["memory"]
                )
            }
            if len(inputs) != len(spec["regions"]):
                raise Invalid(
                    "Every initial memory row needs exactly one complete named relation region"
                )
            for r in spec["regions"]:
                at = r[side]
                if at not in inputs or inputs[at][0].size() != 8 * r["size"]:
                    raise Invalid(
                        "Relation extents must match complete initial memory rows"
                    )
                if overlaps(at, r["size"], self.stack, self.stack_size):
                    if (
                        r["left"] != r["right"]
                        or not self.stack
                        <= at
                        < at + r["size"]
                        <= self.stack + self.stack_size
                    ):
                        raise Unsupported(
                            "Stack storage cannot relocate or straddle the stack window"
                        )
                if any(
                    overlaps(at, r["size"], a, len(raw)) for a, raw in analysis.chunks
                ):
                    raise Unsupported("A RAM relation cannot overlap selected code")
            if any(
                overlaps(a, len(raw), self.stack, self.stack_size)
                for a, raw in analysis.chunks
            ):
                raise Unsupported(
                    "Layout relation cannot alias code and the stack window"
                )
            analysis.relation_domain = [
                (r[side], r["size"]) for r in spec["regions"]
            ] + [(self.stack, self.stack_size)]
            analysis.fixed_segments = {
                n: analysis.spec["registers"][n] for n in ("cs", "ds", "es", "ss")
            }
            analysis.fixed_stack = (self.stack, self.stack_size)
        li = {a: (e, r) for (a, e), r in zip(left.input_memory, left.spec["memory"])}
        ri = {a: (e, r) for (a, e), r in zip(right.input_memory, right.spec["memory"])}
        for r in spec["regions"]:
            le, ld = li[r["left"]]
            re, rd = ri[r["right"]]
            # Matching entire declarations makes the relation total on both
            # domains, including multi-byte bounds. Never silently intersect.
            if {k: v for k, v in ld.items() if k != "address"} != {
                k: v for k, v in rd.items() if k != "address"
            }:
                raise Unsupported(
                    "Related RAM rows need identical byte/scalar domains; embedded pointer translation is unsupported"
                )
            constraints.append(le == re)
        for p in spec["pointers"]:
            offsets = []
            domains = []
            for side, analysis in self.analyses.items():
                offset = self.pointer_offset(analysis, analysis.initial, p, side)
                offsets.append(offset)
                domains.append(
                    (
                        analysis.initial.solver.min(offset),
                        analysis.initial.solver.max(offset),
                    )
                )
            if domains[0] != domains[1]:
                raise Unsupported(
                    "Input pointer offset domains differ; narrowing to their intersection is not allowed"
                )
            constraints.append(offsets[0] == offsets[1])
        for name in left.register_names:
            if name not in pointer_names:
                constraints.append(left.input_regs[name] == right.input_regs[name])
        both = (
            list(left.initial.solver.constraints)
            + list(right.initial.solver.constraints)
            + constraints
        )
        left.initial.add_constraints(*both)
        right.initial.add_constraints(*both)
        if not left.initial.solver.satisfiable():
            raise Invalid("Input correspondence is unsatisfiable")

    def pointer_offset(self, analysis, state, pointer, side):
        region = self.regions.get(pointer["region"])
        if region is None:
            raise Invalid("Pointer names an unknown relation region")
        at, size = region[side], region["size"]
        if overlaps(at, size, self.stack, self.stack_size):
            raise Unsupported("Declared relocated pointers cannot target stack storage")
        # Preserve physical aliasing through DS/ES, not just equal numeric offsets.
        value = claripy.ZeroExt(16, analysis.read_register(state, pointer["register"]))
        segment = claripy.ZeroExt(16, analysis.read_register(state, pointer["segment"]))
        address = (segment << 4) + value
        invalid = claripy.Or(
            value == 0, claripy.ULT(address, at), claripy.UGE(address, at + size)
        )
        if state.solver.satisfiable(extra_constraints=[invalid]):
            raise Unsupported(
                "Pointer domain is not proved inside its named region (null/one-past/stack/code unsupported)"
            )
        return address - at

    def validate_memory(self, rows):
        for row in rows:
            candidates = [
                r
                for r in self.spec["regions"]
                if r["left"] <= row["left"]
                and row["left"] + row["size"] <= r["left"] + r["size"]
            ]
            if len(candidates) != 1:
                raise Unsupported(
                    "Final memory must be a bounded subregion of a declared input relation"
                )
            r = candidates[0]
            if row["right"] - r["right"] != row["left"] - r["left"]:
                raise Unsupported(
                    "Final memory does not preserve the declared region offset/extent"
                )

    def native_pointer(self, pointer, side, result):
        r = self.regions[pointer["region"]]
        values = result["registers"]
        address = (values[pointer["segment"]] << 4) + values[pointer["register"]]
        if (
            values[pointer["register"]] == 0
            or not r[side] <= address < r[side] + r["size"]
        ):
            return None
        return address - r[side]

    def summary(self):
        return {
            "kind": "explicit real16 fixed-segment relation",
            **self.spec,
            "stack": {"address": self.stack, "size": self.stack_size},
            "limits": [
                "Only declared near register pointers translate; all other inputs are raw scalars/bytes",
                "Segment registers and stack window stay fixed; accesses must stay in named RAM or the stack",
                "No embedded-pointer, null, one-past, code-pointer or general pointer equivalence",
                "Ordered effects retain raw physical addresses; literal bytes are never normalized",
            ],
        }
