import json
import pytest
from test_binquery import fixture
from test_targets import registers
from binquery.queries import targets, query
from binquery.model import contract


@pytest.mark.parametrize("opcode", ["ff2e0020", "ff1e0020"])
def test_memory_far_pointer_uses_segment_and_offset_and_native_frame(tmp_path, opcode):
    p, _, s = fixture(
        tmp_path,
        opcode,
        registers=registers(),
        memory=[dict(address=0x42000, hex="00200020")],
    )
    r = targets(p, s, 0x11000)
    assert r["complete"], r["issues"]
    row = r["targets"][0]
    assert (row["kind"], row["segment"], row["offset"], row["address"]["offset"]) == (
        "far",
        0x2000,
        0x2000,
        0x22000,
    )
    assert row["replay"]["matched"]
    if opcode.startswith("ff1e"):
        writes = [
            x for x in row["witness"]["expected"]["events"] if x["kind"] == "write"
        ]
        assert [w["value"] for w in writes] == [0x1000, 0x1004]


def test_far_return_reads_both_words_and_pops_frame(tmp_path):
    p, _, s = fixture(
        tmp_path,
        "cb",
        registers=registers(),
        memory=[dict(address=0x78000, hex="00200020")],
    )
    r = targets(p, s, 0x11000)
    # Unicorn memory hooks currently corrupt the RETF destination fetch.
    # Keep the observation incomplete rather than bypass independent replay.
    assert not r["complete"] and not r["targets"][0]["replay"]["matched"]
    assert r["targets"][0]["witness"]["expected"]["registers"]["sp"] == 0x8004


def test_far_call_executes_original_helper_and_returns(tmp_path):
    helper = tmp_path / "helper.bin"
    helper.write_bytes(bytes.fromhex("b80900cb"))
    p, c, s = fixture(
        tmp_path,
        "9a0020002040",
        registers=registers(),
        claims=[dict(kind="return_equals", register="ax", value=10)],
    )
    d = json.loads(c.read_text())
    d["stops"][0]["kind"] = "return"
    d["code"].append(dict(address=0x22000, size=4, file="helper.bin", segment=0x2000))
    c.write_text(json.dumps(d))
    r = query(p, contract(c)[0])
    assert not r["issues"], r["issues"]
    assert r["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"


def test_unknown_memory_and_unsupported_prefix_are_not_targets(tmp_path):
    p, _, s = fixture(tmp_path, "ff2e0020", registers=registers())
    r = targets(p, s, 0x11000)
    assert not r["complete"] and not r["targets"]
    p, _, s = fixture(tmp_path, "66ff2e0020", name="bad", registers=registers())
    r = targets(p, s, 0x11000)
    assert not r["complete"]


def test_physically_aliasing_far_pairs_keep_distinct_identities(tmp_path):
    # Two mutable pointer writes produce the same physical address via distinct
    # segment:offset pairs. Enumeration must not collapse the pairs.
    code = "83f800750ec70600200020c70602200020eb0cc70600201020c7060220ff1fff2e0020"
    p, _, s = fixture(
        tmp_path,
        code,
        registers=registers(ax=dict(symbolic=True, min=0, max=1)),
        memory=[dict(address=0x42000, hex="00000000")],
    )
    r = targets(p, s, 0x1101F)
    assert r["complete"], r["issues"]
    assert {(x["segment"], x["offset"]) for x in r["targets"]} == {
        (0x2000, 0x2000),
        (0x1FFF, 0x2010),
    }
    assert {x["address"]["offset"] for x in r["targets"]} == {0x22000}
    assert all(x["replay"]["matched"] for x in r["targets"])


def test_far_pointer_segment_override_is_effective(tmp_path):
    p, _, s = fixture(
        tmp_path,
        "26ff2e0020",
        registers=registers(),
        memory=[
            dict(address=0xA2000, hex="00200020"),
            dict(address=0x42000, hex="00300030"),
        ],
    )
    r = targets(p, s, 0x11000)
    assert r["complete"], r["issues"]
    assert r["targets"][0]["segment"] == 0x2000 and r["targets"][0]["offset"] == 0x2000
    assert r["targets"][0]["replay"]["matched"]


@pytest.mark.parametrize(
    "opcode,frame,stop,segment,reason",
    [
        ("ea00000020", "00000020", 0x20000, 0x2000, "unchanged segment"),
        ("ca0001", "00200010", 0x12000, 0x1000, "SP leaves"),
    ],
)
def test_far_transfer_at_boundary_enforces_layout_relation(
    tmp_path, opcode, frame, stop, segment, reason
):
    from binquery.queries import compare

    helper = tmp_path / "helper.bin"
    helper.write_bytes(b"\x90")
    binary, config, _ = fixture(
        tmp_path,
        opcode,
        registers=registers(),
        memory=[
            {"address": 0x40200, "hex": "00"},
            {"address": 0x78000, "hex": frame},
        ],
    )
    raw = json.loads(config.read_text())
    raw["code"].append(
        {"address": stop + 0x2000, "size": 1, "file": "helper.bin", "segment": segment}
    )
    raw["stops"] = [{"address": stop, "kind": "boundary"}]
    config.write_text(json.dumps(raw))
    spec = contract(config)[0]
    comparison = {
        "schema": 1,
        "relation": {
            "regions": [
                {"name": "data", "left": 0x40200, "right": 0x40200, "size": 1},
                {"name": "frame", "left": 0x78000, "right": 0x78000, "size": 4},
            ],
            "stack": {"address": 0x77FF0, "size": 0x20},
        },
    }
    result = compare(binary, binary, spec, spec, ["ax"], comparison=comparison)
    assert result["status"] == "INCONCLUSIVE"
    assert reason in str(result["left"]["issues"])
