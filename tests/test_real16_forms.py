import copy
import json
import subprocess
import sys

import pytest

from binquery.engine import Analysis, FLAGS
from binquery.flags import require_defined
from binquery.model import Unsupported
from binquery.queries import compare, query, _pin
from binquery.replay import replay
from test_binquery import fixture, preserved


def replay_defined_flags(analysis, state, expected_undefined=()):
    selected = state.copy()
    witness = analysis.witness(selected)
    _pin(selected, analysis, witness)
    flags = {}
    for name in FLAGS:
        if name in expected_undefined:
            with pytest.raises(Unsupported, match="Undefined flag"):
                analysis.read_register(selected, name)
        else:
            flags[name] = selected.solver.eval(analysis.read_register(selected, name))
    witness["expected"]["flags"] = flags
    result = replay(analysis, witness)
    assert result["matched"], result["errors"]
    return result


@pytest.mark.parametrize("op", ["shl", "shr"])
@pytest.mark.parametrize("size", [1, 2])
@pytest.mark.parametrize("memory", [False, True])
@pytest.mark.parametrize("count", [0, 1, 2, 7, 8, 15, 16, 31, 32, 33, 255])
def test_shift_counts_defined_flags_and_replay(tmp_path, op, size, memory, count):
    prefix = "d2" if size == 1 else "d3"
    modrm = (
        ("26" if op == "shl" else "2e") if memory else ("e0" if op == "shl" else "e8")
    )
    code = prefix + modrm + ("0001" if memory else "")
    value = (1 << (size * 8 - 1)) | 1
    a, _, spec = fixture(
        tmp_path,
        code,
        flags=0x247,
        shift_count="masked5",
        memory=[{"address": 0x40100, "hex": value.to_bytes(size, "little").hex()}]
        if memory
        else [],
    )
    spec["registers"].update(ax=value, cx=count)
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues and len(analysis.leaves) == 1
    effective = count & 31
    undefined = ({"of"} if effective > 1 else set()) | (
        {"cf"} if effective >= size * 8 else set()
    )
    result = replay_defined_flags(analysis, analysis.leaves[0], undefined)
    mask = (1 << (size * 8)) - 1
    expected = ((value << effective) if op == "shl" else (value >> effective)) & mask
    actual = (
        result["events"][-1]["value"] if memory else result["registers"]["ax"] & mask
    )
    assert actual == expected
    if memory:
        assert [e["kind"] for e in result["events"]] == ["read", "write"]


@pytest.mark.parametrize(
    "code", ["d1e8", "d0e8", "c1e801", "c0e801", "c1e800", "c0e800"]
)
def test_shr_defined_overflow_repair(tmp_path, code):
    a, _, spec = fixture(tmp_path, code, flags=0x202)
    spec["registers"]["ax"] = 0x8080
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues
    r = replay_defined_flags(analysis, analysis.leaves[0])
    assert r["flags"]["of"] == (0 if code.endswith("00") else 1)


@pytest.mark.parametrize("count", [32, 33, 255])
def test_unselected_cpu_masking_never_assumed(tmp_path, count):
    a, _, spec = fixture(tmp_path, "d3e8", claims=[preserved()])
    spec["registers"]["cx"] = count
    r = query(a, spec)
    assert not r["complete"] and "masked5" in r["issues"][0]["reason"]


def test_unbounded_symbolic_count_rejected_but_bounded_count_supported(tmp_path):
    a, _, spec = fixture(tmp_path, "d3e8", claims=[preserved()])
    assert not query(a, spec)["complete"]
    spec["registers"]["cx"] = {"symbolic": True, "min": 0, "max": 31}
    assert query(a, spec)["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"
    spec["claims"] = [preserved("of")]
    with pytest.raises(Unsupported, match="Undefined flag OF"):
        query(a, spec)


@pytest.mark.parametrize("size", [1, 2])
@pytest.mark.parametrize("memory", [False, True])
@pytest.mark.parametrize(
    "a_value,b_value", [(0, 0xFFFF), (1, 1), (0xFFFF, 2), (0x80FF, 0x1234)]
)
def test_unsigned_mul_values_and_only_defined_flags(
    tmp_path, size, memory, a_value, b_value
):
    code = ("f6" if size == 1 else "f7") + ("260001" if memory else "e3")
    mask = (1 << (size * 8)) - 1
    a, _, spec = fixture(
        tmp_path,
        code,
        memory=[
            {"address": 0x40100, "hex": (b_value & mask).to_bytes(size, "little").hex()}
        ]
        if memory
        else [],
    )
    spec["registers"].update(ax=a_value, bx=b_value)
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues
    r = replay_defined_flags(analysis, analysis.leaves[0], {"sf", "zf", "pf"})
    product = (a_value & mask) * (b_value & mask)
    assert r["registers"]["ax"] == product & 0xFFFF
    if size == 2:
        assert r["registers"]["dx"] == product >> 16


@pytest.mark.parametrize("branch", ["740190", "780190", "7a0190"])
def test_mul_undefined_flag_branch_cannot_establish(tmp_path, branch):
    a, _, spec = fixture(tmp_path, "f7e3" + branch, claims=[preserved()])
    r = query(a, spec)
    assert not r["complete"] and "Undefined flag" in r["issues"][0]["reason"]


@pytest.mark.parametrize(
    "code", ["f7e3720190", "f7e3700190", "f7e385c0740190", "f7e383f800740190"]
)
def test_defined_or_overwritten_flags_remain_usable(tmp_path, code):
    a, _, spec = fixture(tmp_path, code, claims=[preserved()])
    assert query(a, spec)["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"


@pytest.mark.parametrize("count,complete", [(0, False), (1, True), (2, True)])
def test_shift_conditional_flag_definedness_after_mul(tmp_path, count, complete):
    a, _, spec = fixture(tmp_path, "f7e3d3e8740190", claims=[preserved()])
    spec["registers"]["cx"] = count
    assert query(a, spec)["complete"] == complete


def test_shr_symbolic_zero_or_one_preserves_or_sets_of(tmp_path):
    a, _, spec = fixture(tmp_path, "d3e8", flags=0x202)
    spec["registers"].update(ax=0x8000, cx={"symbolic": True, "min": 0, "max": 1})
    spec["claims"] = [preserved("of")]
    result = query(a, spec)
    assert result["claims"][0]["status"] == "REFUTED"
    assert result["claims"][0]["witness"]["registers"]["cx"] == 1


@pytest.mark.parametrize(
    "code", ["fc", "fd", "f6d0", "f7d0", "f6160001", "f7160001", "8507", "8400"]
)
def test_direction_test_and_not_forms(tmp_path, code):
    a, _, spec = fixture(
        tmp_path, code, flags=0xA03, memory=[{"address": 0x40100, "hex": "0180"}]
    )
    spec["registers"].update(bx=0x100, si=0)
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues
    replay_defined_flags(analysis, analysis.leaves[0])


def test_concrete_ds_es_updates_save_restore_and_aliases(tmp_path):
    # Save DS/ES, switch DS to a distinct segment with the same target address,
    # copy DS to ES, read the aliased word, then restore both segments.
    a, _, spec = fixture(
        tmp_path,
        "1e06b801408ed88ec0a1f000071f",
        memory=[{"address": 0x40100, "hex": "3412"}],
    )
    analysis = Analysis(a, spec).explore()
    assert not analysis.issues
    r = replay_defined_flags(analysis, analysis.leaves[0])
    assert (
        r["registers"]["ax"] == 0x1234
        and r["registers"]["ds"] == 0x4000
        and r["registers"]["es"] == 0xA000
    )


@pytest.mark.parametrize("code", ["8ed8", "8ec0"])
def test_symbolic_segment_updates_remain_unsupported(tmp_path, code):
    a, _, spec = fixture(tmp_path, code, claims=[preserved()])
    r = query(a, spec)
    assert not r["complete"] and "Symbolic DS/ES" in r["issues"][0]["reason"]


def test_byte_versus_word_read_difference_is_replayed(tmp_path):
    memory = [{"address": 0x40100, "symbolic": True, "size": 2}]
    a, _, sa = fixture(tmp_path, "a00001", memory=memory)
    b, _, sb = fixture(tmp_path, "a1000125ff00", name="b", memory=memory)
    sa["registers"]["ax"] = sb["registers"]["ax"] = 0
    assert compare(a, b, sa, sb, ["ax"])["status"] == "EQUIVALENT_WITHIN_MODEL"
    r = compare(a, b, sa, sb, ["ax"], effects=True)
    assert r["status"] == "DIFFERENT" and all(
        v["matched"] for v in r["replay"].values()
    )
    assert r["replay"]["left"]["events"][0]["size"] == 1
    assert r["replay"]["right"]["events"][0]["size"] == 2


def test_saved_replay_cannot_bypass_portable_shift_policy(tmp_path):
    a, _, spec = fixture(tmp_path, "d3e8")
    spec["registers"]["cx"] = {"symbolic": True, "min": 0, "max": 32}
    masked = copy.deepcopy(spec)
    masked["shift_count"] = "masked5"
    analysis = Analysis(a, masked).explore()
    state = analysis.leaves[0]
    witness = analysis.witness(state, [analysis.input_regs["cx"] == 32])
    native = replay(Analysis(a, spec), witness)
    assert not native["matched"] and "portable model" in " ".join(native["errors"])
