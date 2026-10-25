"""Target-domain observations preserve execution guards and independent replay."""

import copy
import pytest
from test_binquery import fixture
from binquery.queries import targets
from binquery.model import Invalid


def registers(**kw):
    return dict(cs=0x1000, ds=0x4000, ss=0x7000, es=0xA000, sp=0x8000, **kw)


def test_multiple_destinations_without_bodies_and_partial_limit(tmp_path):
    p, _, s = fixture(
        tmp_path,
        "ffe0",
        registers=registers(ax=dict(symbolic=True, min=0x2000, max=0x2002)),
    )
    r = targets(p, s, 0x11000)
    assert r["complete"] and [t["offset"] for t in r["targets"]] == [
        0x2000,
        0x2001,
        0x2002,
    ]
    assert all(t["replay"]["matched"] for t in r["targets"])
    r = targets(p, s, 0x11000, 2)
    assert not r["complete"] and not r["domain_exhausted"] and len(r["targets"]) == 2


def test_guards_restrict_domain_and_outside_index_is_unreachable(tmp_path):
    # cmp ax,2; ja boundary; jmp ax
    p, _, s = fixture(
        tmp_path,
        "83f8027702ffe0",
        registers=registers(ax=dict(symbolic=True, min=0, max=4)),
    )
    r = targets(p, s, 0x11005)
    assert r["complete"] and [t["offset"] for t in r["targets"]] == [0, 1, 2]
    s["registers"]["ax"] = 4
    assert targets(p, s, 0x11005)["status"] == "UNREACHABLE_WITHIN_SCOPE"


def test_missing_segment_is_not_an_empty_target_set(tmp_path):
    regs = registers(ax=0x1000)
    del regs["ds"]
    p, _, s = fixture(tmp_path, "ffe0", registers=regs)
    with pytest.raises(Invalid, match="segment"):
        targets(p, s, 0x11000)


def test_interior_and_outside_targets_are_retained(tmp_path):
    p, _, s = fixture(tmp_path, "ffe0", registers=registers(ax=0x1001))
    r = targets(p, s, 0x11000)
    assert r["complete"] and r["targets"][0]["destination"] == "interior_instruction"


def test_mutable_table_observes_writes_and_missing_memory_is_incomplete(tmp_path):
    # mov word [2000],3000; jmp word [2000]
    p, _, s = fixture(
        tmp_path,
        "c70600200030ff260020",
        registers=registers(),
        memory=[dict(address=0x42000, hex="0010")],
    )
    r = targets(p, s, 0x11006)
    assert r["complete"] and r["targets"][0]["offset"] == 0x3000
    assert r["targets"][0]["replay"]["matched"]
    p, _, s = fixture(tmp_path, "ff260020", name="missing", registers=registers())
    r = targets(p, s, 0x11000)
    assert not r["complete"] and not r["targets"]


def test_equal_offsets_different_segment_have_distinct_physical_targets(tmp_path):
    p, _, s = fixture(tmp_path, "ffe0", registers=registers(ax=0x2000))
    a = targets(p, s, 0x11000)
    other = copy.deepcopy(s)
    other["registers"]["cs"] = 0x1100
    b = targets(p, other, 0x11000)
    assert a["targets"][0]["address"]["offset"] == 0x12000
    assert b["targets"][0]["address"]["offset"] == 0x13000


def test_nonaligned_call_and_far_transfer_remain_unsupported(tmp_path):
    p, _, s = fixture(tmp_path, "ffd0", registers=dict(registers(ax=0x2000), cs=0x1100))
    r = targets(p, s, 0x11000)
    assert not r["complete"] and any(
        "return offsets" in x["reason"] for x in r["issues"]
    )
    from binquery.model import Unsupported

    p, _, s = fixture(tmp_path, "ea00200010", name="far", registers=registers())
    assert targets(p, s, 0x11000)["complete"]
