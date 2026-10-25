import copy
import json
import pickle

import pytest
from angr import claripy

from binquery.execution import Execution
from binquery.execution_contract import load


def fixture(
    tmp_path,
    raw,
    *,
    arch="x86:LE:16:Real Mode",
    memory=None,
    registers=None,
    permissions="rwx",
    stops=True,
    **options,
):
    binary = tmp_path / "analysis.bin"
    binary.write_bytes(bytes.fromhex(raw))
    address = 0x11000 if arch != "AMD64" else 0x400000
    regs = dict.fromkeys(["ax", "bx", "cx", "dx", "si", "di", "bp"], 0)
    regs.update(cs=0x1000, ds=0x4000, ss=0x7000, es=0xA000, sp=0x8000)
    if arch == "AMD64":
        regs = dict.fromkeys(
            [
                "rax",
                "rbx",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
                "rbp",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
            ],
            0,
        )
        regs["rsp"] = 0x700000
    regs.update(registers or {})
    d = {
        "schema": 2,
        "architecture": arch,
        "code": [
            {
                "address": address,
                "size": len(binary.read_bytes()),
                "permissions": permissions,
            }
        ],
        "memory": memory or [],
        "entries": [
            {
                "name": "main",
                "program": "synthetic",
                "space": "ram",
                "load_context": "main",
                "address": address,
                "registers": regs,
                "flags": 0x202,
            }
        ],
        "stops": [{"address": address + len(binary.read_bytes()), "kind": "boundary"}]
        if stops
        else [],
    }
    d.update(options)
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(d))
    return Execution(load(binary, path)), binary, path


def test_full_domain(tmp_path):
    e, _, _ = fixture(
        tmp_path,
        "83f805730583c003eb0231c0a30002",
        registers={"ax": {"symbolic": True}},
        memory=[{"address": 0x40200, "hex": "0000"}],
    )
    e.run()
    assert not e.pending
    assert len(e.finished) == 2, [(x[2], x[3]) for x in e.finished]
    assert all(k == "stop" for _, s, k, r in e.finished), [
        (k, r) for _, s, k, r in e.finished
    ]
    assert e.steps == 7
    low, high = sorted(
        (s for _, s, _, _ in e.finished),
        key=lambda s: s.solver.min(e.engines[0].input_regs["ax"]),
    )
    ax = e.engines[0].input_regs["ax"]
    assert (low.solver.min(ax), low.solver.max(ax)) == (0, 4)
    assert (high.solver.min(ax), high.solver.max(ax)) == (5, 65535)
    assert not low.solver.satisfiable(extra_constraints=[low.regs.ax != ax + 3])
    assert not high.solver.satisfiable(extra_constraints=[high.regs.ax != 0])


def test_fair_loop(tmp_path):
    e, _, _ = fixture(
        tmp_path,
        "83f8007402ebfe90",
        registers={"ax": {"symbolic": True}},
        limits={"steps": 5},
    )
    e.run()
    assert any(k == "stop" for _, _, k, _ in e.finished)
    assert e.pending
    before = e.steps
    e.run(8)
    assert e.steps > before
    assert sum(k == "stop" for _, _, k, _ in e.finished) == 1


def test_concrete_cycle(tmp_path):
    e, _, _ = fixture(tmp_path, "ebfe", stops=False)
    e.run()
    assert not e.pending
    assert e.finished[0][2] == "cycle"


def test_patch(tmp_path):
    e, _, _ = fixture(tmp_path, "2ec606071007b80100")
    e.run()
    assert [(k, r) for _, _, k, r in e.finished] == [("stop", "boundary")]
    assert e.finished[0][1].solver.eval(e.finished[0][1].regs.ax) == 7
    assert e.finished[0][1].globals["trace"][-1]["bytes"] == "b80700"


def test_readonly_patch(tmp_path):
    e, _, _ = fixture(tmp_path, "2ec606071007b80100", permissions="rx")
    e.run()
    assert e.finished[0][2] == "unsupported"
    assert "permission" in e.finished[0][3]


def test_amd64(tmp_path):
    e, _, _ = fixture(
        tmp_path, "4883c001", arch="AMD64", registers={"rax": {"symbolic": True}}
    )
    e.run()
    assert e.finished[0][2] == "stop", e.finished[0][3]
    s = e.finished[0][1]
    assert not s.solver.satisfiable(
        extra_constraints=[s.regs.rax != e.engines[0].input_regs["rax"] + 1]
    )


def test_checkpoint_resume(tmp_path):
    from binquery.execution_report import report
    from binquery.execution_store import read_report, restore, save

    e, _, _ = fixture(
        tmp_path,
        "83f805730583c003eb0231c0a30002",
        registers={"ax": {"symbolic": True}},
        memory=[{"address": 0x40200, "hex": "0000"}],
    )
    e.run(2)
    checkpoint = tmp_path / "run.bq"
    save(e, checkpoint, report(e))
    assert read_report(checkpoint)["metrics"]["pending_paths"] == 2
    restored = restore(checkpoint).run(128)
    r = report(restored)
    assert r["complete"], r["paths"]
    assert restored.steps == 7
    assert all(p["replay"]["matched"] for p in r["paths"])
    assert all(len(p["events"]) == 1 for p in r["paths"])
    assert all("smt2" in p for p in r["paths"])


def test_patch_replay(tmp_path):
    from binquery.execution_report import report

    e, _, _ = fixture(tmp_path, "2ec606071007b80100")
    r = report(e.run())
    assert r["complete"], r


def test_queries_and_writers(tmp_path):
    from binquery.execution_queries import ask, dot, graph
    from binquery.execution_report import report

    # Word store, partial overwrite, read, same-value overwrite, read again.
    raw = "c70600023412c606010256a10002c6060102568b1e0002"
    e, _, _ = fixture(tmp_path, raw, memory=[{"address": 0x40200, "hex": "0000"}])
    r = report(e.run())
    assert r["complete"], r["paths"][0].get("replay")
    answer = ask(r, {"kind": "last-write", "site": 0x1100B})
    assert answer["status"] == "ESTABLISHED"
    assert [b["writers"][0]["writer"] for b in answer["matches"][0]["bytes"]] == [
        "m0",
        "m1",
    ]
    answer = ask(r, {"kind": "last-write", "site": 0x11013})
    assert [b["writers"][0]["writer"] for b in answer["matches"][0]["bytes"]] == [
        "m0",
        "m3",
    ]
    assert (
        ask(
            r,
            {
                "kind": "access",
                "access": "write",
                "range": "0x40200:2",
                "expect": "always",
            },
        )["status"]
        == "ESTABLISHED"
    )
    assert (
        ask(
            r,
            {
                "kind": "access",
                "access": "read",
                "range": "0x40204:2",
                "expect": "never",
            },
        )["status"]
        == "ESTABLISHED"
    )
    assert "digraph" in dot(graph(r, "memory"))


def test_partial_query_semantics(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    e, _, _ = fixture(
        tmp_path,
        "a10002ebfe",
        memory=[{"address": 0x40200, "hex": "0000"}],
        registers={"bx": {"symbolic": True}},
    )
    r = report(e.run(1))
    q = {"kind": "access", "access": "read", "range": "0x40200:2"}
    assert ask(r, q)["status"] == "ESTABLISHED"
    assert ask(r, dict(q, expect="never"))["status"] == "REFUTED"
    assert ask(r, dict(q, expect="always"))["status"] == "ESTABLISHED"
    q["range"] = "0x40202:2"
    assert ask(r, dict(q, expect="never"))["status"] == "INCONCLUSIVE"
    assert ask(r, dict(q, expect="never", within_steps=1))["status"] == "ESTABLISHED"


def test_symbolic_patch_remainder(tmp_path):
    from binquery.execution_report import report

    # Patches MOV AX's immediate with the input AX, then executes it.
    e, _, _ = fixture(
        tmp_path,
        "2ea30510b80000",
        registers={"ax": {"symbolic": True, "min": 0, "max": 7}},
        limits={"variants": 2},
    )
    e.run()
    assert len(e.pending) == 1
    assert e.pending[0][2] == "instruction variant limit"
    assert len(e.finished) == 2
    while e.pending:
        e.run()
    r = report(e)
    assert r["complete"], r["paths"]
    assert len(e.finished) == 8
    assert sorted(s.solver.eval(s.regs.ax) for _, s, _, _ in e.finished) == list(
        range(8)
    )
    assert all(p["replay"]["matched"] for p in r["paths"])


def test_correlated_instruction_bytes(tmp_path):
    # AX is copied to DX then the same low byte is stored in both immediate
    # bytes. Only 0x0000 and 0x0101, never mixed-byte values, may execute.
    # Two 4-byte stores followed by MOV: immediate addresses 1009,100A.
    e, _, _ = fixture(
        tmp_path,
        "2ea209102ea20a10b80000",
        registers={"ax": {"symbolic": True, "min": 0, "max": 1}},
    )
    e.run()
    assert not e.pending
    assert sorted(
        s.solver.eval(s.regs.ax) for _, s, k, _ in e.finished if k == "stop"
    ) == [0, 257]


@pytest.mark.parametrize(
    "arch,raw",
    [("x86:LE:16:Real Mode", "e80300eb0290c3"), ("AMD64", "e803000000eb0290c3")],
)
def test_calls(tmp_path, arch, raw):
    from binquery.execution_report import report

    memory = (
        [{"address": 0x77FF0, "hex": "00" * 16}]
        if arch != "AMD64"
        else [{"address": 0x6FFFF0, "hex": "00" * 16}]
    )
    e, _, _ = fixture(tmp_path, raw, arch=arch, memory=memory)
    r = report(e.run())
    assert r["complete"], r["paths"]
    assert [x["kind"] for x in r["paths"][0]["trace"]][:2] == ["call", "return"]


def test_ports(tmp_path):
    from binquery.execution_report import report

    e, _, _ = fixture(
        tmp_path,
        "e460e661",
        ports=[
            {"port": 0x60, "width": 1, "domain": [1, 7]},
            {"port": 0x61, "width": 1, "write": True},
        ],
    )
    r = report(e.run())
    assert r["complete"], r["paths"]
    assert r["paths"][0]["io"][0]["kind"] == "port-in"
    assert len(r["paths"][0]["io"]) == 2
    assert r["paths"][0]["replay"]["matched"]


def test_interrupt(tmp_path):
    from binquery.execution_report import report

    # INT 20; skip handler; handler adds one and IRET.
    raw = "cd20eb0440cf9090"
    e, _, _ = fixture(
        tmp_path,
        raw,
        memory=[
            {"address": 0x80, "hex": "04100010"},
            {"address": 0x77FF0, "hex": "00" * 16},
        ],
        interrupts=[0x20],
    )
    r = report(e.run())
    assert r["complete"], r["paths"]
    assert "interrupt" in [t["kind"] for t in r["paths"][0]["trace"]]
    assert "interrupt-return" in [t["kind"] for t in r["paths"][0]["trace"]]


def test_changed_input_and_atomic_save(tmp_path, monkeypatch):
    import binquery.execution_store as store
    from binquery.execution_report import report
    from binquery.execution_store import read_report, restore, save
    from binquery.model import Invalid

    e, binary, _ = fixture(tmp_path, "90")
    checkpoint = tmp_path / "run.bq"
    save(e, checkpoint, report(e))
    original = checkpoint.read_bytes()
    monkeypatch.setattr(
        store.os,
        "replace",
        lambda *_: (_ for _ in ()).throw(OSError("simulated interruption")),
    )
    with pytest.raises(OSError):
        save(e.run(), checkpoint, report(e))
    assert checkpoint.read_bytes() == original
    binary.write_bytes(b"\x91")
    with pytest.raises(Invalid, match="input changed"):
        restore(checkpoint)
    assert read_report(checkpoint)["schema"] == 2


def test_multiple_contexts(tmp_path):
    from binquery.execution_report import report

    e, binary, config = fixture(tmp_path, "40")
    d = json.loads(config.read_text())
    second = copy.deepcopy(d["entries"][0])
    second["name"] = "other"
    second["load_context"] = "overlay2"
    second["registers"]["ax"] = 10
    d["entries"].append(second)
    config.write_text(json.dumps(d))
    e = Execution(load(binary, config))
    r = report(e.run())
    assert r["complete"]
    assert [p["registers"]["ax"] for p in r["paths"]] == [1, 11]
    assert len({p["entry"]["load_context"] for p in r["paths"]}) == 2


def test_interrupt_resume_is_transactional(tmp_path, monkeypatch):
    e, _, _ = fixture(
        tmp_path,
        "2ea30510b80000",
        registers={"ax": {"symbolic": True, "min": 0, "max": 3}},
    )
    original = e.engines[0].execute
    count = 0

    def interrupt_second_variant(state, ins):
        nonlocal count
        count += 1
        if count == 3:
            raise KeyboardInterrupt()
        return original(state, ins)

    monkeypatch.setattr(e.engines[0], "execute", interrupt_second_variant)
    e.run()
    assert not e.finished
    assert len(e.pending) == 1
    monkeypatch.setattr(e.engines[0], "execute", original)
    e.run()
    assert sorted(
        s.solver.eval(s.regs.ax) for _, s, k, _ in e.finished if k == "stop"
    ) == [0, 1, 2, 3]
    assert e.steps == 5


def test_undefined_af_is_not_exposed_as_fact(tmp_path):
    e, _, _ = fixture(
        tmp_path, "31c09c58", memory=[{"address": 0x77FF0, "hex": "00" * 16}]
    )
    e.run()
    from binquery.execution_report import report

    r = report(e)
    assert r["complete"] and r["paths"][0]["registers"]["ax"]["undefined"]
    assert r["paths"][0]["replay"]["matched"]


def test_near_call_segment_wrap(tmp_path):
    _e, binary, config = fixture(
        tmp_path, "e8000090", memory=[{"address": 0x77FF0, "hex": "00" * 16}]
    )
    d = json.loads(config.read_text())
    d["entries"][0]["address"] = 0x1FFFD
    d["code"] = [
        {"address": 0x1FFFD, "size": 3},
        {"address": 0x10000, "offset": 3, "size": 1},
    ]
    d["stops"] = [{"address": 0x10001, "kind": "boundary"}]
    config.write_text(json.dumps(d))
    from binquery.execution_report import report

    r = report(Execution(load(binary, config)).run())
    assert r["complete"], r["paths"]
    assert r["paths"][0]["trace"][0]["target"] == 0x10000


def test_modified_code_range(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    e, _, _ = fixture(tmp_path, "2ec606071007b80100")
    r = report(e.run())
    yes = ask(r, {"kind": "modified-code", "range": "0x11006:3"})
    no = ask(r, {"kind": "modified-code", "range": "0x50000:2"})
    assert yes["status"] == "ESTABLISHED"
    assert yes["matches"][0]["changed_offsets"] == [1]
    assert no["status"] == "REFUTED" and not no["matches"]


def test_cycle_last_writer_and_prelude(tmp_path):
    from binquery.execution_queries import ask, graph
    from binquery.execution_report import report

    # One-time prelude, then read/store-same-value/back edge.
    e, _, _ = fixture(
        tmp_path,
        "c606000200a00002c606000200ebf6",
        memory=[{"address": 0x40200, "hex": "00"}],
        stops=False,
    )
    r = report(e.run())
    assert r["complete"] and r["paths"][0]["cycle_start"] == 1
    a = ask(r, {"kind": "last-write", "site": 0x11005})
    writers = a["matches"][0]["bytes"][0]["writers"]
    assert [(w["writer"], w.get("visit")) for w in writers] == [
        ("m0", None),
        ("m2", "subsequent cycle"),
    ]
    a = ask(r, {"kind": "last-write", "site": 0x11005, "within_steps": 2})
    assert [w["writer"] for w in a["matches"][0]["bytes"][0]["writers"]] == ["m0"]
    assert any(
        e.get("visit") == "subsequent cycle" for e in graph(r, "memory")["edges"]
    )


def test_cycle_fetch_same_value_write(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    # First fetch NOP, rewrite it to NOP, loop back.
    e, _, _ = fixture(tmp_path, "902ec606001090ebf7", stops=False)
    r = report(e.run())
    assert r["complete"]
    a = ask(r, {"kind": "modified-code", "range": "0x11000:1"})
    assert a["status"] == "REFUTED"  # same value, not changed code
    assert any(
        w.get("visit") == "subsequent cycle"
        for m in a["matches"]
        for b in m["bytes"]
        for w in b["writers"]
    )


def test_symbolic_memory_default_and_alias(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    # DS:0200 and ES:0100 resolve to the same physical byte.
    e, _, _ = fixture(
        tmp_path,
        "a0000226a20101a00102",
        registers={"es": 0x4010},
        memory=[
            {"address": 0x40200, "symbolic": True},
            {"address": 0x40201, "hex": "00"},
        ],
    )
    r = report(e.run())
    assert r["complete"], r["paths"]
    a = ask(r, {"kind": "last-write", "site": 0x11007})
    assert a["matches"][0]["bytes"][0]["writers"][0]["writer"] == "m1"
    assert all(w["replay"]["matched"] for w in a["witnesses"])


def test_checkpoint_nary_and_full_event_equivalence(tmp_path):
    import io

    from binquery.execution_report import report
    from binquery.execution_store import StatePickler, restore, save

    x, y, z = (claripy.BVS(n, 8) for n in ("x", "y", "z"))
    for original in (
        x + y + z,
        x * y * z,
        x & y & z,
        x | y | z,
        x ^ y ^ z,
        claripy.And(x == 0, y == 0, z == 0),
        claripy.Or(x == 0, y == 0, z == 0),
    ):
        buf = io.BytesIO()
        StatePickler(buf).dump(original)
        restored = pickle.loads(buf.getvalue())
        solver = claripy.Solver()
        solver.add(original != restored)
        assert not solver.satisfiable()
    e, _, _ = fixture(
        tmp_path,
        "83f805730583c003eb0231c0a30002",
        registers={"ax": {"symbolic": True}},
        memory=[{"address": 0x40200, "hex": "0000"}],
    )
    whole = report(Execution(copy.deepcopy(e.config)).run())
    e.run(2)
    save(e, tmp_path / "run.bq", report(e))
    resumed = report(restore(tmp_path / "run.bq").run(128))
    for a, b in zip(whole["paths"], resumed["paths"]):
        for key in (
            "events",
            "trace",
            "registers",
            "conditions",
            "input_memory",
            "smt2",
            "outcome",
            "depth",
        ):
            assert a[key] == b[key], key


def test_query_symbolic_remainder_and_port_counterexample(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    e, _, _ = fixture(
        tmp_path,
        "2ea30510b80000",
        registers={"ax": {"symbolic": True, "min": 0, "max": 1}},
        limits={"variants": 1},
    )
    r = report(e.run())
    q = {"kind": "modified-code", "range": "0x11004:3", "expect": "always"}
    assert ask(r, q)["status"] in {"INCONCLUSIVE", "REFUTED"}
    e.run()
    assert ask(report(e), q)["status"] == "REFUTED"
    e, _, _ = fixture(
        tmp_path,
        "e4603c017403a0000290",
        ports=[{"port": 0x60, "width": 1, "domain": [1, 7]}],
        memory=[{"address": 0x40200, "hex": "00"}],
    )
    a = ask(
        report(e.run()),
        {"kind": "access", "access": "read", "range": "0x40200:1", "expect": "always"},
    )
    assert a["status"] == "REFUTED"
    assert {w["io"][0]["value"] for w in a["witnesses"]} == {1, 7}
    assert all(w["replay"]["matched"] for w in a["witnesses"])


def test_far_transfer_and_shared_tail(tmp_path):
    from binquery.execution_report import report

    _e, binary, config = fixture(
        tmp_path, "9a00002012eb0143cb", memory=[{"address": 0x77FF0, "hex": "00" * 16}]
    )
    d = json.loads(config.read_text())
    d["code"] = [
        {"address": 0x11000, "size": 7},
        {"address": 0x12200, "offset": 7, "size": 2},
    ]
    d["stops"] = [{"address": 0x11008, "kind": "boundary"}]
    config.write_text(json.dumps(d))
    r = report(Execution(load(binary, config)).run())
    assert r["complete"], r["paths"]
    trace = r["paths"][0]["trace"]
    assert trace[0]["target_segment"] == 0x1220 and trace[2]["kind"] == "return"


def test_alternate_overlapping_entries(tmp_path):
    from binquery.execution_report import report

    _e, binary, config = fixture(tmp_path, "b8909090")
    d = json.loads(config.read_text())
    other = copy.deepcopy(d["entries"][0])
    other["name"] = "inside"
    other["address"] += 1
    d["entries"].append(other)
    config.write_text(json.dumps(d))
    r = report(Execution(load(binary, config)).run())
    assert r["complete"]
    assert {p["trace"][0]["bytes"] for p in r["paths"]} == {"b89090", "90"}


def test_caps_and_bad_occurrence(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report
    from binquery.model import Invalid

    e, _, _ = fixture(tmp_path, "909090", limits={"events": 1})
    r = report(e.run())
    assert not r["complete"] and e.pending
    assert e.steps == 1
    e.config["limits"]["events"] = 10
    assert report(e.run())["complete"]
    with pytest.raises(Invalid, match="occurrence"):
        ask(report(e), {"kind": "flow", "to": 0x11003, "event": "x9", "path": "p0"})


def test_portable_report_incompatible_versions(tmp_path, monkeypatch):
    import binquery.execution_store as store
    from binquery.execution_report import report
    from binquery.model import Invalid

    e, _, _ = fixture(tmp_path, "90")
    p = tmp_path / "run.bq"
    store.save(e.run(), p, report(e))
    monkeypatch.setattr(store, "versions", lambda: {"changed": True})
    with pytest.raises(Invalid, match="versions"):
        store.restore(p)
    assert store.read_report(p)["complete"]


def test_native_replay_rejects_wrong_witness(tmp_path):
    from binquery.execution_replay import replay_witness
    from binquery.execution_report import report

    e, _, _ = fixture(
        tmp_path, "c606000201a00002", memory=[{"address": 0x40200, "hex": "00"}]
    )
    r = report(e.run())
    w = r["paths"][0]["witness"]
    for field, value in [("bytes", "90"), ("target", 0x11009)]:
        bad = copy.deepcopy(w)
        bad["trace"][0][field] = value
        assert not replay_witness(e.engines[0], bad)["matched"]
    bad = copy.deepcopy(w)
    bad["expected"]["events"][0]["address"] += 1
    assert not replay_witness(e.engines[0], bad)["matched"]


@pytest.mark.parametrize("flags,expected", [(2, 0x40202), (0x402, 0x401FE)])
def test_string_store_direction(tmp_path, flags, expected):
    from binquery.execution_report import report

    _e, binary, p = fixture(
        tmp_path,
        "ab",
        registers={"es": 0x4000, "di": 0x200, "ax": 0x1234},
        memory=[{"address": 0x40200, "hex": "0000"}],
    )
    d = json.loads(p.read_text())
    d["entries"][0]["flags"] = flags
    p.write_text(json.dumps(d))
    r = report(Execution(load(binary, p)).run())
    assert r["complete"], r["paths"]
    assert r["paths"][0]["registers"]["di"] == expected - 0x40000
    assert r["paths"][0]["events"][0]["value"] == 0x1234


def test_checkpoint_size_rejection_preserves_prior(tmp_path):
    from binquery.execution_report import report
    from binquery.execution_store import save
    from binquery.model import Incomplete

    e, _, _ = fixture(tmp_path, "90")
    p = tmp_path / "run.bq"
    save(e, p, report(e))
    before = p.read_bytes()
    e.config["limits"]["checkpoint_mb"] = 0
    with pytest.raises(Incomplete, match="size limit"):
        save(e.run(), p, report(e))
    assert p.read_bytes() == before


def test_analysis_cli_lifecycle(tmp_path):
    import subprocess
    import sys

    _e, binary, contract = fixture(
        tmp_path,
        "83f805730583c003eb0231c0a30002",
        registers={"ax": {"symbolic": True}},
        memory=[{"address": 0x40200, "hex": "0000"}],
    )
    checkpoint = tmp_path / "run.bq"

    def call(*args):
        p = subprocess.run(
            [sys.executable, "-m", "binquery", *map(str, args)],
            capture_output=True,
            check=False,
            text=True,
            cwd=tmp_path,
        )
        return p.returncode, json.loads(p.stdout)

    code, r = call(
        "analyze",
        binary,
        "--contract",
        contract,
        "--save",
        checkpoint,
        "--steps",
        2,
        "--json",
    )
    assert code == 2 and r["schema"] == 2
    code, r = call(
        "query",
        "--analysis",
        checkpoint,
        "--kind",
        "access",
        "--access",
        "write",
        "--range",
        "0x40200:2",
        "--expect",
        "never",
        "--json",
    )
    assert code == 2
    code, r = call("analyze", "--resume", checkpoint, "--steps", 128, "--json")
    assert code == 0 and r["metrics"]["symbolic_steps"] == 7
    before = checkpoint.read_bytes()
    code, repeated = call("analyze", "--resume", checkpoint, "--steps", 128, "--json")
    assert code == 0 and checkpoint.read_bytes() == before
    assert repeated["metrics"] == r["metrics"]
    code, r = call("graph", checkpoint, "--format", "json")
    assert code == 0 and r["nodes"] and r["paths"][0]["smt2"]
    q = tmp_path / "questions.json"
    q.write_text(
        json.dumps(
            [
                {
                    "kind": "access",
                    "access": "write",
                    "range": "0x40200:2",
                    "expect": "always",
                },
                {"kind": "access", "access": "read", "range": "0x50000:2"},
            ]
        )
    )
    code, r = call("query", "--analysis", checkpoint, "--questions", q, "--json")
    assert code == 1 and [a["status"] for a in r["answers"]] == [
        "ESTABLISHED",
        "REFUTED",
    ]
    code, r = call("analyze", "--resume", checkpoint, "--steps", 1, "--json")
    assert code == 3


def test_replay_rejects_execution_from_data(tmp_path):
    from binquery.execution_replay import replay_witness
    from binquery.execution_report import report

    e, _, _ = fixture(tmp_path, "90", memory=[{"address": 0x12000, "hex": "9090"}])
    w = report(e.run())["paths"][0]["witness"]
    w["trace"][0].update(instruction=0x12000, target=0x12001)
    assert not replay_witness(e.engines[0], w)["matched"]


def test_query_keeps_late_counterexample(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    _e, binary, p = fixture(
        tmp_path,
        "a0000290",
        memory=[{"address": 0x40200, "hex": "00"}],
        limits={"replays": 1},
    )
    d = json.loads(p.read_text())
    for i in range(5):
        row = copy.deepcopy(d["entries"][0])
        row["name"] = f"other{i}"
        if i == 4:
            row["address"] += 3
        d["entries"].append(row)
    p.write_text(json.dumps(d))
    r = report(Execution(load(binary, p)).run())
    a = ask(
        r,
        {"kind": "access", "access": "read", "range": "0x40200:1", "expect": "always"},
    )
    assert a["status"] == "REFUTED"
    assert a["witnesses"][0]["interaction"] is False
    assert a["witnesses"][0]["replay"]["matched"]


def test_resume_finishes_interrupted_native_verification(tmp_path):
    from binquery.cli import parser
    from binquery.execution_cli import run
    from binquery.execution_report import report
    from binquery.execution_store import save

    e, _, _ = fixture(tmp_path, "90")
    checkpoint = tmp_path / "run.bq"
    saved = save(e.run(), checkpoint, report(e, replay=False))
    assert saved["complete"] and saved["metrics"]["replays"] == 0
    assert "replay" not in saved["paths"][0]
    args = parser().parse_args(["analyze", "--resume", str(checkpoint)])
    finished = run(args, bounded=True)
    assert finished["complete"] and finished["metrics"]["replays"] == 1
    assert finished["paths"][0]["replay"]["matched"]
    assert finished["metrics"]["symbolic_steps"] == saved["metrics"]["symbolic_steps"]
    before = checkpoint.read_bytes()
    repeated = run(args, bounded=True)
    assert checkpoint.read_bytes() == before
    assert repeated["metrics"] == finished["metrics"]


@pytest.mark.parametrize(
    "prefix,segment", [("", "ds"), ("2e", "cs"), ("26", "es"), ("36", "ss")]
)
def test_xlat_segment_wrap_and_following_load(tmp_path, prefix, segment):
    regs = {"bx": 0xFFFF, "ax": 1}
    bases = {"ds": 0x40000, "cs": 0x10000, "es": 0xA0000, "ss": 0x70000}
    e, _, _ = fixture(
        tmp_path,
        prefix + "d7a20002a00002",
        registers=regs,
        memory=[
            {"address": bases[segment], "hex": "5a"},
            {"address": 0x40200, "hex": "00"},
        ],
    )
    from binquery.execution_report import report

    r = report(e.run())
    assert r["complete"] and r["paths"][0]["replay"]["matched"]
    assert r["paths"][0]["registers"]["ax"] == 0x5A
    assert r["paths"][0]["events"][0]["address"] == bases[segment]


@pytest.mark.parametrize("raw", ["2e8316101000", "2ed13e1010"])
def test_arithmetic_data_on_executable_page(tmp_path, raw):
    e, _, _ = fixture(tmp_path, raw, memory=[{"address": 0x11010, "hex": "ffff"}])
    from binquery.execution_report import report

    r = report(e.run())
    assert r["complete"] and r["paths"][0]["replay"]["matched"]
    assert [x["kind"] for x in r["paths"][0]["events"]] == ["read", "write"]


@pytest.mark.parametrize("count", [1, 16, 31])
def test_sar_carry_remains_defined(tmp_path, count):
    e, _, _ = fixture(tmp_path, "d3f8720090", registers={"ax": 0x8001, "cx": count})
    from binquery.execution_report import report

    r = report(e.run())
    assert r["complete"] and r["paths"][0]["replay"]["matched"]
    assert r["paths"][0]["trace"][0]["after_flags"]["cf"] == 1


@pytest.mark.parametrize("raw", ["f3ac", "67d7", "87060002", "2e90", "2ee80000"])
def test_new_forms_keep_unqualified_prefixes_and_memory_xchg_rejected(tmp_path, raw):
    e, _, _ = fixture(tmp_path, raw)
    from binquery.execution_report import report

    r = report(e.run())
    assert not r["complete"] and r["paths"][0]["outcome"] == "unsupported"


def test_ignored_segment_cmp_and_register_exchange(tmp_path):
    e, _, _ = fixture(tmp_path, "263c0e86c4", registers={"ax": 0x120E})
    from binquery.execution_report import report

    r = report(e.run())
    assert r["complete"] and r["paths"][0]["replay"]["matched"]
    assert r["paths"][0]["registers"]["ax"] == 0xE12


def test_large_initial_buffer_has_serializable_query_witness(tmp_path):
    from binquery.execution_queries import ask
    from binquery.execution_report import report

    e, _, _ = fixture(
        tmp_path, "a00002", memory=[{"address": 0x40200, "hex": ("ab" * 8192)}]
    )
    r = json.loads(json.dumps(report(e.run())))
    assert r["complete"]
    answer = ask(
        r,
        {"kind": "access", "access": "read", "range": "0x40200:1", "expect": "always"},
    )
    assert (
        answer["status"] == "ESTABLISHED"
        and answer["witnesses"][0]["replay"]["matched"]
    )
    json.dumps(answer)


@pytest.mark.parametrize("raw,flag", [("b102d3f8700090", "OF"), ("b110d3e011c0", "CF")])
def test_new_forms_keep_undefined_flags_explicit(tmp_path, raw, flag):
    from binquery.execution_report import report

    e, _, _ = fixture(tmp_path, raw)
    r = report(e.run())
    assert not r["complete"] and r["paths"][0]["outcome"] == "unsupported"
    assert flag in r["paths"][0]["reason"]


@pytest.mark.parametrize("direction", [0, 1])
def test_lods_direction_and_width(tmp_path, direction):
    from binquery.execution_report import report

    e, _, _ = fixture(
        tmp_path,
        ("fd" if direction else "fc") + "acad",
        registers={"si": 0x202},
        memory=[{"address": 0x40200, "hex": "1122334455"}],
    )
    r = report(e.run())
    assert r["complete"] and r["paths"][0]["replay"]["matched"]
    assert r["paths"][0]["registers"]["ax"] == (0x3322 if direction else 0x5544)
    assert r["paths"][0]["registers"]["si"] == (0x1FF if direction else 0x205)


def test_address_limit_retains_frontier_and_resume_applies_policies(tmp_path):
    from binquery.cli import parser
    from binquery.execution_cli import run
    from binquery.execution_report import report
    from binquery.execution_store import restore, save

    e, _, _ = fixture(
        tmp_path,
        "8a07",
        registers={"bx": {"symbolic": True, "min": 0x100, "max": 0x103}},
        memory=[{"address": 0x40100, "hex": "01020304"}],
        limits={"addresses": 1, "solver_ms": 1000},
    )
    e.run()
    assert not e.finished
    assert len(e.pending) == 1
    assert "address enumeration limit" in e.pending[0][2]
    assert not e.pending[0][1].globals["trace"]
    checkpoint = tmp_path / "limited.bq"
    save(e, checkpoint, report(e))
    args = parser().parse_args(
        [
            "analyze",
            "--resume",
            str(checkpoint),
            "--addresses",
            "4",
            "--solver-ms",
            "60000",
        ]
    )
    result = run(args, bounded=True)
    assert result["complete"], result["issues"]
    assert all(p["replay"]["matched"] for p in result["paths"])
    restored = restore(checkpoint)
    state = restored.finished[0][1]
    assert state.solver._solver.timeout == 60000
    assert state.memory.read_strategies[0]._limit == 4
    assert state.memory.write_strategies[0]._limit == 4
    for address, value in zip(range(0x100, 0x104), range(1, 5)):
        bx = restored.engines[0].input_regs["bx"]
        assert (
            state.solver.eval(state.regs.al, extra_constraints=[bx == address]) == value
        )


def test_run_refreshes_retained_state_limits(tmp_path):
    e, _, _ = fixture(tmp_path, "909090", limits={"addresses": 1, "solver_ms": 1000})
    e.run(1)
    e.config["limits"].update(addresses=4, solver_ms=60000)
    e.run(2)
    state = e.pending[0][1]
    assert state.solver._solver.timeout == 60000
    assert state.memory.read_strategies[0]._limit == 4
    assert state.memory.write_strategies[0]._limit == 4
