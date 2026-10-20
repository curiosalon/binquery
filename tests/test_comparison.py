import copy
import json
import subprocess
import sys

import pytest

from binquery.discovery import paired_example
from binquery.engine import Analysis
from binquery.model import Invalid, Unsupported, contract
from binquery.observations import comparison_contract
from binquery.queries import compare
from binquery.replay import replay
from test_binquery import fixture


def bundle(tmp_path, kind="layout"):
    example = paired_example(kind)
    for name, content in example["files"].items():
        p = tmp_path / name
        p.write_bytes(
            bytes.fromhex(content["hex"])
            if "hex" in content
            else json.dumps(content["json"]).encode()
        )
    return (
        tmp_path / "left.bin",
        tmp_path / "right.bin",
        contract(tmp_path / "left.json")[0],
        contract(tmp_path / "right.json")[0],
        example["files"]["comparison.json"]["json"],
    )


def run(pair, *, effects=False, observe=()):
    a, b, sa, sb, comparison = pair
    return compare(a, b, sa, sb, list(observe), effects, comparison)


def test_final_ram_is_separate_from_access_order(tmp_path):
    pair = bundle(tmp_path, "final-memory")
    r = run(pair, effects=True)
    assert r["status"] == "DIFFERENT"
    assert r["comparisons"]["final_memory"]["status"] == "EQUIVALENT_WITHIN_MODEL"
    assert r["comparisons"]["ordered_memory_effects"]["status"] == "DIFFERENT"
    assert all(x["matched"] for x in r["replay"].values())
    assert [x["size"] for x in r["replay"]["left"]["events"]] == [2]
    assert [x["size"] for x in r["replay"]["right"]["events"]] == [1, 1]
    assert r["replay"]["left"]["final_memory"][0]["hex"] == "0102"


@pytest.mark.parametrize("byte", [0, 1])
def test_changed_output_or_neighbor_byte_replays(tmp_path, byte):
    pair = bundle(tmp_path, "final-memory")
    raw = bytearray(pair[1].read_bytes())
    raw[4 + 5 * byte] ^= 1
    pair[1].write_bytes(raw)
    r = run(pair)
    assert r["status"] == "DIFFERENT"
    assert r["comparisons"]["final_memory"]["differing_bytes"][0]["offset"] == byte
    assert all(x["matched"] for x in r["replay"].values())
    w = copy.deepcopy(r["witness"]["right"])
    w["expected"]["memory"][0]["hex"] = "ffff"
    bad = replay(Analysis(pair[1], pair[3]), w)
    assert not bad["matched"] and "Final memory differs" in " ".join(bad["errors"])


def test_omitted_neighbor_write_is_disclosed(tmp_path):
    pair = bundle(tmp_path, "final-memory")
    pair[4]["memory"][0]["size"] = 1
    raw = bytearray(pair[1].read_bytes())
    raw[9] = 99
    pair[1].write_bytes(raw)
    r = run(pair)
    assert r["status"] == "EQUIVALENT_WITHIN_MODEL"
    assert r["writes_outside_final_memory"]["right"]["distinct_sites"] == 1
    assert r["writes_outside_final_memory"]["right"]["sites"][0]["address"] == 0x40101
    assert "unproved" in r["scope"]


def test_final_observation_must_be_initialized_on_every_path(tmp_path):
    a, _, sa = fixture(tmp_path, "90")
    config = {
        "schema": 1,
        "memory": [{"name": "out", "left": 0x40100, "right": 0x40100, "size": 1}],
    }
    with pytest.raises(Unsupported, match="uninitialized"):
        compare(a, a, sa, sa, [], comparison=config)
    # Written final bytes may be observed even without an initial declaration.
    a, _, sa = fixture(tmp_path, "c606000101")
    b, _, sb = fixture(tmp_path, "c606000102", name="b")
    r = compare(a, b, sa, sb, [], comparison=config)
    assert r["status"] == "DIFFERENT" and all(
        x["matched"] for x in r["replay"].values()
    )


def test_final_ram_rejects_code_and_oversized_regions(tmp_path):
    a, _, sa = fixture(tmp_path, "90")
    row = {"name": "out", "left": 0x11000, "right": 0x11000, "size": 1}
    with pytest.raises(Unsupported, match="selected code"):
        compare(a, a, sa, sa, [], comparison={"schema": 1, "memory": [row]})
    row.update(left=0x40000, right=0x40000, size=4097)
    with pytest.raises(Invalid, match="4096"):
        comparison_contract({"schema": 1, "memory": [row]})


def test_layout_storage_and_pointer_observables(tmp_path):
    pair = bundle(tmp_path)
    r = run(pair)
    assert r["status"] == "EQUIVALENT_WITHIN_MODEL" and not r["byte_match"]
    assert r["comparisons"]["pointers"]["status"] == "EQUIVALENT_WITHIN_MODEL"
    # Raw AX and access addresses remain different when selected explicitly.
    r = run(pair, effects=True, observe=["ax"])
    assert r["status"] == "DIFFERENT"
    assert r["comparisons"]["registers"]["status"] == "DIFFERENT"
    assert r["comparisons"]["final_memory"]["status"] == "EQUIVALENT_WITHIN_MODEL"
    assert r["comparisons"]["ordered_memory_effects"]["status"] == "DIFFERENT"
    assert all(x["matched"] for x in r["comparisons"]["registers"]["replay"].values())
    assert (
        r["witness"]["left"]["memory"][1]["hex"]
        == r["witness"]["right"]["memory"][1]["hex"]
    )


def test_layout_wrong_binding_is_not_equivalent(tmp_path):
    pair = bundle(tmp_path)
    # Read from output rather than input on the right. Domains remain symbolic.
    code = bytearray(pair[1].read_bytes())
    code[1] = 0
    pair[1].write_bytes(code)
    r = run(pair)
    assert r["status"] == "DIFFERENT"
    assert r["comparisons"]["final_memory"]["differing_bytes"]
    assert all(x["matched"] for x in r["replay"].values())
    # Correct input correspondence remains visible in the selected joint model.
    for index in (0, 1):
        assert (
            r["witness"]["left"]["memory"][index]["hex"]
            == r["witness"]["right"]["memory"][index]["hex"]
        )


def test_layout_extent_and_alias_ambiguities_reject(tmp_path):
    pair = bundle(tmp_path)
    bad = copy.deepcopy(pair[4])
    bad["relation"]["regions"][0]["size"] = 1
    with pytest.raises(Invalid, match="complete initial"):
        compare(*pair[:4], [], comparison=bad)
    bad = copy.deepcopy(pair[4])
    bad["memory"][0]["right"] += 1
    with pytest.raises(Unsupported, match="offset/extent"):
        compare(*pair[:4], [], comparison=bad)
    bad = copy.deepcopy(pair[4])
    bad["relation"]["regions"][1]["right"] = 0x40201
    with pytest.raises(Invalid, match="Overlapping"):
        compare(*pair[:4], [], comparison=bad)


def test_domain_intersection_and_embedded_pointer_mapping_reject(tmp_path):
    pair = bundle(tmp_path)
    pair[3]["memory"][1]["max"] = 7
    with pytest.raises(Unsupported, match="identical byte/scalar domains"):
        run(pair)
    pair = bundle(tmp_path)
    pair[4]["relation"]["pointers"] = [
        {"address": 0x40120, "segment": "ds", "region": "result"}
    ]
    with pytest.raises(Invalid):
        run(pair)


def pointer_pair(tmp_path):
    a, _, sa = fixture(
        tmp_path, "8a073204", memory=[{"address": 0x40100, "symbolic": True, "size": 4}]
    )
    b, _, sb = fixture(
        tmp_path,
        "8a073204",
        name="b",
        memory=[{"address": 0x40200, "symbolic": True, "size": 4}],
    )
    for spec, start in ((sa, 0x100), (sb, 0x200)):
        spec["registers"].update(
            bx={"symbolic": True, "min": start, "max": start + 3},
            si={"symbolic": True, "min": start, "max": start + 3},
        )
    pointer = lambda name: {"register": name, "segment": "ds", "region": "buffer"}
    comparison = {
        "schema": 1,
        "relation": {
            "regions": [
                {"name": "buffer", "left": 0x40100, "right": 0x40200, "size": 4}
            ],
            "pointers": [pointer("bx"), pointer("si")],
        },
        "pointers": [pointer("bx"), pointer("si")],
    }
    return a, b, sa, sb, comparison


def test_symbolic_near_pointers_preserve_possible_aliases(tmp_path):
    pair = pointer_pair(tmp_path)
    assert run(pair, observe=["ax"])["status"] == "EQUIVALENT_WITHIN_MODEL"
    pair[3]["registers"]["si"] = {"symbolic": True, "min": 0x201, "max": 0x203}
    with pytest.raises(Unsupported, match="offset domains differ"):
        run(pair)


def test_pointer_domain_may_not_escape_to_unknown_or_one_past(tmp_path):
    pair = pointer_pair(tmp_path)
    pair[2]["registers"]["bx"]["max"] = 0x104
    with pytest.raises(Unsupported, match="Pointer domain"):
        run(pair)


def test_different_segment_offsets_preserve_physical_alias(tmp_path):
    pair = pointer_pair(tmp_path)
    for spec, start in ((pair[2], 0xF0), (pair[3], 0x1F0)):
        spec["registers"]["es"] = 0x4001
        spec["registers"]["si"] = {"symbolic": True, "min": start, "max": start + 3}
    pair[4]["relation"]["pointers"][1]["segment"] = "es"
    pair[4]["pointers"][1]["segment"] = "es"
    # Only BX is dereferenced; SI is explicitly an ES-based pointer observable.
    pair[0].write_bytes(bytes.fromhex("8a079090"))
    pair[1].write_bytes(pair[0].read_bytes())
    assert run(pair, observe=["ax"])["status"] == "EQUIVALENT_WITHIN_MODEL"
    pair[3]["registers"]["es"] = 0x4002
    with pytest.raises(Unsupported, match="register bindings"):
        run(pair)


def test_stack_relocation_and_segment_updates_reject(tmp_path):
    pair = bundle(tmp_path)
    for spec, addr in ((pair[2], 0x78000), (pair[3], 0x78002)):
        spec["memory"].append({"address": addr, "hex": "0000"})
    pair[4]["relation"]["regions"].append(
        {"name": "stack", "left": 0x78000, "right": 0x78002, "size": 2}
    )
    with pytest.raises(Unsupported, match="Stack storage"):
        run(pair)
    pair = bundle(tmp_path)
    pair[0].write_bytes(bytes.fromhex("b801408ed890909090"))
    r = run(pair)
    assert r["status"] == "INCONCLUSIVE"
    assert "unchanged segment" in str(r["left"]["issues"])


def test_unmapped_extra_write_prevents_relation_proof(tmp_path):
    pair = bundle(tmp_path)
    # Keep length; place a write outside all mapped RAM instead of the load.
    pair[1].write_bytes(bytes.fromhex("a30004a30002b80002"))
    r = run(pair)
    assert r["status"] == "INCONCLUSIVE" and "relation RAM" in str(r["right"]["issues"])


def test_extra_observed_write_refutes_memory_equality(tmp_path):
    pair = bundle(tmp_path)
    pair[4]["memory"].append(copy.deepcopy(pair[4]["relation"]["regions"][1]))
    # Store input AX to the input region, then copy to output: changes visible input.
    pair[1].write_bytes(bytes.fromhex("a32002a30002b80002"))
    r = run(pair)
    assert r["status"] == "DIFFERENT" and all(
        v["matched"] for v in r["replay"].values()
    )


def test_partial_exploration_cannot_establish_final_memory(tmp_path):
    pair = bundle(tmp_path)
    pair[2]["limits"]["steps"] = 1
    r = run(pair)
    assert r["status"] == "INCONCLUSIVE"
    assert r["comparisons"]["final_memory"]["status"] == "INCONCLUSIVE"


def test_cli_schema_examples_and_saved_pair_replay(tmp_path):
    def cli(*args):
        return subprocess.run(
            [sys.executable, "-m", "binquery", *map(str, args)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

    schema = cli("schema", "--kind", "comparison", "--schema-only")
    assert (
        schema.returncode == 0 and "relation" in json.loads(schema.stdout)["properties"]
    )
    for kind in ("final-memory", "layout"):
        example = cli("example", "--kind", kind, "--json")
        assert example.returncode == 0
        for name, row in json.loads(example.stdout)["files"].items():
            (tmp_path / name).write_bytes(
                bytes.fromhex(row["hex"])
                if "hex" in row
                else json.dumps(row["json"]).encode()
            )
        args = [
            "compare",
            "left.bin",
            "right.bin",
            "--contract",
            "left.json",
            "--right-contract",
            "right.json",
            "--comparison",
            "comparison.json",
            "--json",
        ]
        eq = cli(*args)
        assert eq.returncode == 0, eq.stdout
        different = cli(*args, "--effects")
        assert different.returncode == 1, different.stdout
        (tmp_path / "result.json").write_text(different.stdout)
        for side in ("left", "right"):
            result = cli(
                "replay",
                side + ".bin",
                "--contract",
                side + ".json",
                "--witness",
                "result.json",
                "--side",
                side,
                "--aspect",
                "ordered_memory_effects",
                "--json",
            )
            assert (
                result.returncode == 0 and json.loads(result.stdout)["final_memory"]
            ), result.stdout


def test_raw_zero_pointer_is_rejected_even_at_segment_base(tmp_path):
    a, _, sa = fixture(tmp_path, "90", memory=[{"address": 0x40000, "hex": "00"}])
    b, _, sb = fixture(
        tmp_path, "90", name="b", memory=[{"address": 0x40100, "hex": "00"}]
    )
    sa["registers"]["bx"], sb["registers"]["bx"] = 0, 0x100
    p = {"register": "bx", "segment": "ds", "region": "data"}
    config = {
        "schema": 1,
        "pointers": [p],
        "relation": {
            "regions": [{"name": "data", "left": 0x40000, "right": 0x40100, "size": 1}],
            "pointers": [p],
        },
    }
    with pytest.raises(Unsupported, match="Pointer domain"):
        compare(a, b, sa, sb, [], comparison=config)
    # Also reject a zero produced at the boundary, not just an initial zero.
    sa["registers"]["bx"] = sb["registers"]["bx"] = 1
    a.write_bytes(bytes.fromhex("4b"))
    b.write_bytes(bytes.fromhex("90"))
    config["relation"]["pointers"] = []
    with pytest.raises(Unsupported, match="Pointer domain"):
        compare(a, b, sa, sb, [], comparison=config)


def test_ds_ss_shared_segment_with_bounded_stack_window(tmp_path):
    pair = bundle(tmp_path)
    for spec in (pair[2], pair[3]):
        spec["registers"]["ss"] = 0x4000
    pair[4]["relation"]["stack"] = {"address": 0x47F00, "size": 0x200}
    assert run(pair)["status"] == "EQUIVALENT_WITHIN_MODEL"
    pair[4]["relation"]["stack"] = {"address": 0x40000, "size": 0x8100}
    with pytest.raises(Unsupported, match="Stack storage"):
        run(pair)


@pytest.mark.parametrize(
    "window", [{"address": 0x77F00, "size": 1}, {"address": 0x6FFFF, "size": 0x8100}]
)
def test_bad_stack_window_rejects(tmp_path, window):
    pair = bundle(tmp_path)
    pair[4]["relation"]["stack"] = window
    with pytest.raises(Unsupported, match="[Ss]tack"):
        run(pair)


def test_stack_pointer_escape_cannot_establish(tmp_path):
    pair = bundle(tmp_path)
    pair[4]["pointers"] = []
    pair[0].write_bytes(bytes.fromhex("bc0081909090909090"))
    r = run(pair)
    # SP at the upper boundary is permitted, but outside it is not.
    assert "SP leaves" not in str(r["left"]["issues"])
    pair[0].write_bytes(bytes.fromhex("bc0181909090909090"))
    r = run(pair)
    assert r["status"] == "INCONCLUSIVE" and "SP leaves" in str(r["left"]["issues"])


def test_pointer_observable_offset_difference_replays(tmp_path):
    pair = bundle(tmp_path)
    raw = bytearray(pair[1].read_bytes())
    raw[7] = 1
    pair[1].write_bytes(raw)
    r = run(pair)
    assert r["comparisons"]["pointers"]["status"] == "DIFFERENT"
    assert r["comparisons"]["final_memory"]["status"] == "EQUIVALENT_WITHIN_MODEL"
    assert all(x["matched"] for x in r["replay"].values())


def test_permuted_physical_locations_keep_distinct_input_symbols(tmp_path):
    pair = bundle(tmp_path)
    pair[1].write_bytes(bytes.fromhex("a10001a32001b82001"))
    pair[3]["memory"][0]["address"] = 0x40120
    pair[3]["memory"][1]["address"] = 0x40100
    pair[4]["relation"]["regions"][0]["right"] = 0x40120
    pair[4]["relation"]["regions"][1]["right"] = 0x40100
    pair[4]["memory"][0]["right"] = 0x40120
    assert run(pair)["status"] == "EQUIVALENT_WITHIN_MODEL"
    raw = bytearray(pair[1].read_bytes())
    raw[1] = 0x20
    pair[1].write_bytes(raw)
    r = run(pair)
    assert r["status"] == "DIFFERENT" and all(
        x["matched"] for x in r["replay"].values()
    )


def test_amd64_final_memory_has_independent_replay(tmp_path):
    a, _, sa = fixture(
        tmp_path,
        "c60001",
        arch="AMD64",
        memory=[{"address": 0x600000, "symbolic": True, "size": 1}],
    )
    b, _, sb = fixture(tmp_path, "c60002", name="b", arch="AMD64", memory=sa["memory"])
    sa["registers"]["rax"] = sb["registers"]["rax"] = 0x600000
    config = {
        "schema": 1,
        "memory": [{"name": "out", "left": 0x600000, "right": 0x600000, "size": 1}],
    }
    r = compare(a, b, sa, sb, [], comparison=config)
    assert r["status"] == "DIFFERENT" and all(
        x["matched"] for x in r["replay"].values()
    )
    config["relation"] = {"regions": config["memory"]}
    with pytest.raises(Unsupported, match="real16"):
        compare(a, b, sa, sb, [], comparison=config)
