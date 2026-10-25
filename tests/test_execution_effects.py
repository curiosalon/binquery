import copy

import pytest
import z3

from binquery.execution_queries import ask
from binquery.execution_report import report
from binquery.execution_store import save, restore
from test_execution import fixture


def flag_fixture(tmp_path, code):
    return fixture(tmp_path, code, memory=[{"address": 0x77FE0, "hex": "00" * 32}])[0]


def test_unknown_flag_save_restore_and_resume(tmp_path):
    e = flag_fixture(tmp_path, "31c09c5b539d90")
    e.run(3)
    checkpoint = tmp_path / "flags.bq"
    save(e, checkpoint, report(e))
    r = report(restore(checkpoint).run(128))
    assert r["complete"], r["issues"]
    p = r["paths"][0]
    assert p["unknown_flags"]
    assert p["events"][0]["value"]["undefined"]
    assert p["replay"]["matched"], p["replay"]
    a = ask(r, dict(kind="last-write", site=0x11003, expect="always"))
    assert a["status"] == "ESTABLISHED", a
    assert all(w["replay"]["matched"] for w in a["witnesses"])


def test_unknown_flag_consumption_stops(tmp_path):
    r = report(flag_fixture(tmp_path, "31c09c58a81074019090").run())
    assert not r["complete"]
    assert any("Undefined" in row["reason"] for row in r["issues"])


def test_saved_unknown_overwritten_before_restore(tmp_path):
    r = report(flag_fixture(tmp_path, "31c09c5883e0ef509d90").run())
    assert r["complete"], r["issues"]
    assert r["paths"][0]["replay"]["matched"]


def test_analysis_depth_can_exceed_legacy_limit(tmp_path):
    e, _, _ = fixture(tmp_path, "ebfe", limits={"steps": 8192})
    assert e.config["limits"]["steps"] == 8192
    e.run()
    assert e.finished[0][2] == "cycle"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("c70600020000", "ESTABLISHED"),
        ("c606000200", "REFUTED"),
        ("c70601020000", "REFUTED"),
        ("c70600020100", "REFUTED"),
        ("90", "REFUTED"),
    ],
)
def test_fill_requires_every_write(tmp_path, raw, expected):
    e, _, _ = fixture(tmp_path, raw, memory=[{"address": 0x40200, "hex": "00000000"}])
    r = report(e.run())
    a = ask(
        r,
        dict(
            kind="memory-effect",
            effect="fill",
            range=[0x40200, 2],
            value=0,
            to=0x11000 + len(bytes.fromhex(raw)),
            expect="always",
        ),
    )
    assert a["status"] == expected, a


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("a10002a30003", "ESTABLISHED"),
        ("a10002c70600030000", "REFUTED"),
        ("a10002a30003c606000209", "REFUTED"),
    ],
)
def test_copy_from_symbolic_source(tmp_path, raw, expected):
    e, _, _ = fixture(
        tmp_path,
        raw,
        memory=[
            {"address": 0x40200, "size": 2, "symbolic": True},
            {"address": 0x40300, "hex": "0000"},
        ],
    )
    a = ask(
        report(e.run()),
        dict(
            kind="memory-effect",
            effect="copy",
            source=0x40200,
            range=[0x40300, 2],
            to=0x11000 + len(bytes.fromhex(raw)),
            expect="always",
        ),
    )
    assert a["status"] == expected, a


def test_initialization_frontier_is_not_a_finished_effect(tmp_path):
    e, _, _ = fixture(
        tmp_path, "c7060002000090", memory=[{"address": 0x40200, "hex": "0000"}]
    )
    a = ask(
        report(e.run(1)),
        dict(
            kind="memory-effect",
            effect="fill",
            range=[0x40200, 2],
            value=0,
            to=0x11007,
            expect="always",
        ),
    )
    assert a["status"] == "INCONCLUSIVE"


def test_symbolic_shift_keeps_old_and_new_unknown_flags_distinct(tmp_path):
    e, _, _ = fixture(
        tmp_path,
        "31c09c5bd3e09c58",
        registers={"cx": {"symbolic": True, "min": 0, "max": 1}},
        memory=[{"address": 0x77FE0, "hex": "00" * 32}],
    )
    r = report(e.run())
    assert r["complete"]
    p = r["paths"][0]
    s = z3.Solver()
    s.from_string(p["smt2"])
    from binquery.execution_queries import expr

    ax, bx, cx = (expr(p["registers"][n], 16) for n in ("ax", "bx", "cx"))
    assert s.check(cx == 0, (ax & 16) != (bx & 16)) == z3.unsat
    assert s.check(cx == 1, (ax & 16) != (bx & 16)) == z3.sat


@pytest.mark.parametrize(
    "question,unused",
    [
        ({"kind": "last-write", "site": 0x11000, "range": "0x50000:2"}, "range"),
        (
            {
                "kind": "access",
                "access": "write",
                "range": "0x40200:2",
                "site": 0x11000,
            },
            "site",
        ),
        ({"kind": "flow", "to": 0x11000, "range": "0x40200:2"}, "range"),
        ({"kind": "modified-code", "range": "0x11000:2", "access": "read"}, "access"),
        (
            {
                "kind": "memory-effect",
                "effect": "fill",
                "range": "0x40200:2",
                "value": 0,
                "to": 0x11000,
                "path": "p0",
                "event": "m0",
            },
            "event",
        ),
        (
            {
                "kind": "memory-effect",
                "effect": "fill",
                "range": "0x40200:2",
                "value": 0,
                "to": 0x11000,
                "source": 0x40300,
            },
            "source",
        ),
    ],
)
def test_unused_query_selectors_are_rejected(question, unused):
    from binquery.execution_queries import validate_question
    from binquery.model import Invalid

    with pytest.raises(Invalid, match=f"does not use: {unused}"):
        validate_question(question)
