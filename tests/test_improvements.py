import copy
import json
import subprocess
import sys

import pytest
from angr import claripy

from binquery.discovery import contract_schema, example
from binquery.effects import normalize_arithmetic
from binquery.engine import Analysis, FLAGS
from binquery.model import Unsupported, contract
from binquery.queries import compare, query
from binquery.queries import _pin
from binquery.replay import replay
from test_binquery import fixture, preserved


def arithmetic_code(op, size):
    if op in ("inc", "dec"):
        return ("fe" if size == 1 else "ff") + ("06" if op == "inc" else "0e") + "0001"
    return (
        ("80" if size == 1 else "83")
        + {"add": "06", "sub": "2e", "and": "26", "or": "0e", "xor": "36"}[op]
        + "000101"
    )


@pytest.mark.parametrize("op", ["inc", "dec", "add", "sub", "and", "or", "xor"])
@pytest.mark.parametrize("size", [1, 2])
@pytest.mark.parametrize("case", ["zero", "one", "positive_max", "negative_min", "max"])
def test_memory_arithmetic_boundary_flags_and_effects(tmp_path, op, size, case):
    limit = (1 << (size * 8)) - 1
    value = {
        "zero": 0,
        "one": 1,
        "positive_max": limit // 2,
        "negative_min": limit // 2 + 1,
        "max": limit,
    }[case]
    a, _, spec = fixture(
        tmp_path,
        arithmetic_code(op, size),
        flags=0x203,
        memory=[{"address": 0x40100, "hex": value.to_bytes(size, "little").hex()}],
    )
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues and len(analysis.leaves) == 1
    state = analysis.leaves[0]
    w = analysis.witness(state)
    w["expected"]["flags"] = {
        n: state.solver.eval(analysis.read_register(state, n)) for n in FLAGS
    }
    native = replay(analysis, w)
    assert native["matched"], native["errors"]
    assert [e["kind"] for e in native["events"]] == ["read", "write"]
    assert native["events"][0]["value"] == value


def test_consumer_inc_word_reproducer_and_saved_replay(tmp_path):
    a, config, spec = fixture(
        tmp_path,
        "ff060001",
        memory=[{"address": 0x40100, "hex": "0100"}],
        claims=[preserved("ax"), {"kind": "no_read", "instruction": 0x11000}],
    )
    output = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "query",
            str(a),
            "--contract",
            str(config),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    result = json.loads(output.stdout)
    assert output.returncode == 1
    assert [c["status"] for c in result["claims"]] == [
        "ESTABLISHED_WITHIN_MODEL",
        "REFUTED",
    ]
    witness = tmp_path / "witness.json"
    witness.write_text(output.stdout)
    replayed = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "replay",
            str(a),
            "--contract",
            str(config),
            "--witness",
            str(witness),
            "--claim",
            "1",
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert replayed.returncode == 0 and json.loads(replayed.stdout)["matched"]


@pytest.mark.parametrize(
    "code,size",
    [
        ("00060001", 1),
        ("28060001", 1),
        ("20060001", 1),
        ("08060001", 1),
        ("30060001", 1),
        ("01060001", 2),
        ("29060001", 2),
        ("21060001", 2),
        ("09060001", 2),
        ("31060001", 2),
        ("810600013412", 2),
        ("812e00013412", 2),
        ("812600013412", 2),
        ("810e00013412", 2),
        ("813600013412", 2),
        ("83060001ff", 2),
        ("832e0001ff", 2),
    ],
)
def test_register_and_immediate_forms_with_symbolic_values(tmp_path, code, size):
    a, _, spec = fixture(
        tmp_path, code, memory=[{"address": 0x40100, "size": size, "symbolic": True}]
    )
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues and len(analysis.leaves) == 1
    state = analysis.leaves[0].copy()
    w = analysis.witness(state)
    _pin(state, analysis, w)
    w["expected"]["flags"] = {
        n: state.solver.eval(analysis.read_register(state, n)) for n in FLAGS
    }
    assert replay(analysis, w)["matched"]


def test_normalization_preserves_separate_instruction_effects(tmp_path):
    a, _, spec = fixture(
        tmp_path,
        "ff060001ff060001",
        memory=[{"address": 0x40100, "hex": "ffff"}],
        claims=[{"kind": "no_read", "instruction": 0x11004}],
    )
    result = query(a, spec)
    native = result["claims"][0]["replay"]
    assert native["matched"]
    assert [(e["step"], e["kind"], e["value"]) for e in native["events"]] == [
        (1, "read", 65535),
        (1, "write", 0),
        (2, "read", 0),
        (2, "write", 1),
    ]


def test_memory_arithmetic_symbolic_inputs_and_carry_counterexample(tmp_path):
    memory = [{"address": 0x40100, "size": 2, "symbolic": True}]
    a, _, sa = fixture(tmp_path, "ff060001", memory=memory)
    b, _, sb = fixture(tmp_path, "8306000101", name="b", memory=memory)
    assert (
        compare(a, b, sa, sb, ["ax"], effects=True)["status"]
        == "EQUIVALENT_WITHIN_MODEL"
    )
    r = compare(a, b, sa, sb, ["cf"], effects=True)
    assert r["status"] == "DIFFERENT"
    assert r["witness"]["left"]["memory"][0]["hex"] == "ffff"
    assert r["replay"]["left"]["matched"] and r["replay"]["right"]["matched"]
    sa["claims"] = [{"kind": "no_read", "instruction": 0x11000}]
    assert query(a, sa)["claims"][0]["status"] == "REFUTED"


def test_bounded_symbolic_destination_and_segment_alias(tmp_path):
    memory = [{"address": 0x40100, "size": 4, "symbolic": True}]
    regs = {
        "cs": 0x1000,
        "ds": 0x4000,
        "ss": 0x4001,
        "es": 0xA000,
        "sp": 0x8000,
        "bp": 0xF0,
        "bx": {"symbolic": True, "min": 0x100, "max": 0x102},
    }
    a, _, spec = fixture(
        tmp_path,
        "ff07",
        memory=memory,
        registers=regs,
        claims=[{"kind": "no_read", "instruction": 0x11000}],
    )
    assert query(a, spec)["claims"][0]["replay"]["matched"]
    spec["registers"]["bx"] = 0x100
    b, _, other = fixture(
        tmp_path, "ff4600", name="b", memory=memory, registers=spec["registers"]
    )
    assert (
        compare(a, b, spec, other, ["ax", "cf", "zf", "of"], effects=True)["status"]
        == "EQUIVALENT_WITHIN_MODEL"
    )


def test_different_memory_write_values_remain_observable(tmp_path):
    memory = [{"address": 0x40100, "size": 2, "symbolic": True}]
    a, _, sa = fixture(tmp_path, "ff060001", memory=memory)
    b, _, sb = fixture(tmp_path, "ff0e0001", name="b", memory=memory)
    result = compare(a, b, sa, sb, [], effects=True)
    assert result["status"] == "DIFFERENT"
    assert result["replay"]["left"]["matched"] and result["replay"]["right"]["matched"]


@pytest.mark.parametrize(
    "mutation",
    [
        "address",
        "size",
        "post_value",
        "old_value",
        "extra_write",
        "missing_read",
        "instruction",
        "step",
    ],
)
def test_normalizer_rejects_unproved_effect_changes(tmp_path, mutation):
    a, _, spec = fixture(
        tmp_path, "ff060001", memory=[{"address": 0x40100, "hex": "0100"}]
    )
    analysis = Analysis(a, spec)
    state = analysis.initial
    addr, old, new = claripy.BVV(0x40100, 32), claripy.BVV(1, 16), claripy.BVV(2, 16)
    read = (1, "read", 0x11000, addr, 2, old)
    write = (1, "write", 0x11000, addr, 2, new)
    post = (1, "read", 0x11000, addr, 2, new)
    rows = [read, read, write, post]
    if mutation == "address":
        rows[-1] = post[:3] + (addr + 1,) + post[4:]
    elif mutation == "size":
        rows[-1] = post[:4] + (1,) + post[5:]
    elif mutation == "post_value":
        rows[-1] = post[:5] + (old,)
    elif mutation == "old_value":
        rows[1] = read[:5] + (new,)
    elif mutation == "extra_write":
        rows.append(write)
    elif mutation == "missing_read":
        rows = [write, post]
    elif mutation == "instruction":
        rows[-1] = post[:2] + (0x11001,) + post[3:]
    else:
        rows[-1] = (2,) + post[1:]
    with pytest.raises(Unsupported, match="effect shape"):
        normalize_arithmetic(state, analysis.instructions[0x11000], rows)


@pytest.mark.parametrize("arch", ["real16", "AMD64"])
def test_native_discovery_example_is_runnable(tmp_path, arch):
    result = subprocess.run(
        [sys.executable, "-m", "binquery", "example", "--arch", arch, "--json"],
        capture_output=True,
        text=True,
    )
    bundle = json.loads(result.stdout)
    assert result.returncode == 0 and bundle["status"] == "DESCRIBED"
    config = tmp_path / "model.json"
    model = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "example",
            "--arch",
            arch,
            "--contract-only",
        ],
        capture_output=True,
        text=True,
    )
    config.write_text(model.stdout)
    assert json.loads(model.stdout) == bundle["contract"] == example(arch)
    binary = tmp_path / "nop.bin"
    binary.write_bytes(bytes.fromhex(bundle["binary_hex"]))
    spec, _ = contract(config)
    assert query(binary, spec)["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"


def test_schema_and_help_are_native(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "binquery", "schema", "--json"],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
        and json.loads(result.stdout)["contract_schema"] == contract_schema()
    )
    raw = subprocess.run(
        [sys.executable, "-m", "binquery", "schema", "--schema-only"],
        capture_output=True,
        text=True,
    )
    assert json.loads(raw.stdout) == contract_schema()
    help_result = subprocess.run(
        [sys.executable, "-m", "binquery", "query", "--help"],
        capture_output=True,
        text=True,
    )
    assert (
        "binquery schema" in help_result.stdout
        and "binquery example" in help_result.stdout
    )
    embedded = help_result.stdout.split("Save this JSON as model.json:\n", 1)[
        1
    ].splitlines()[0]
    config = tmp_path / "from-help.json"
    config.write_text(embedded)
    binary = tmp_path / "nop.bin"
    binary.write_bytes(b"\x90")
    assert (
        query(binary, contract(config)[0])["claims"][0]["status"]
        == "ESTABLISHED_WITHIN_MODEL"
    )
