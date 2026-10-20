import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from binquery.engine import Analysis
from binquery.model import Invalid, Unsupported, contract
from binquery.queries import compare, query

ROOT = Path(__file__).resolve().parents[1]


def fixture(
    tmp_path,
    code,
    *,
    name="a",
    arch="x86:LE:16:Real Mode",
    memory=(),
    claims=(),
    **changes,
):
    path = tmp_path / (name + ".bin")
    path.write_bytes(bytes.fromhex(code))
    address = 0x11000 if arch != "AMD64" else 0x400000
    regs = (
        {"cs": 0x1000, "ds": 0x4000, "ss": 0x7000, "es": 0xA000, "sp": 0x8000}
        if arch != "AMD64"
        else {"rsp": 0x700000}
    )
    spec = {
        "schema": 1,
        "architecture": arch,
        "entry": address,
        "code": [{"address": address, "size": len(path.read_bytes())}],
        "stops": [{"address": address + len(path.read_bytes()), "kind": "boundary"}],
        "registers": regs,
        "flags": 0x202,
        "memory": list(memory),
        "claims": list(claims),
    }
    spec.update(changes)
    config = tmp_path / (name + ".json")
    config.write_text(json.dumps(spec))
    return path, config, contract(config)[0]


def preserved(name="si"):
    return {"kind": "preserved", "register": name}


def test_equivalent_distinct_sequences(tmp_path):
    a, _, sa = fixture(tmp_path, "8bc303c0")
    b, _, sb = fixture(tmp_path, "8bc303c3", name="b")
    r = compare(a, b, sa, sb, ["ax"])
    assert r["status"] == "EQUIVALENT_WITHIN_MODEL" and not r["byte_match"]


def test_overflow_counterexample_and_flags(tmp_path):
    a, _, sa = fixture(tmp_path, "40")  # INC preserves CF
    b, _, sb = fixture(tmp_path, "83c001", name="b")  # ADD computes CF
    assert compare(a, b, sa, sb, ["ax"])["status"] == "EQUIVALENT_WITHIN_MODEL"
    r = compare(a, b, sa, sb, ["ax", "cf"])
    assert r["status"] == "DIFFERENT"
    assert r["witness"]["left"]["registers"]["ax"] == 65535
    assert r["replay"]["left"]["matched"] and r["replay"]["right"]["matched"]


def test_wrong_global_replayed(tmp_path):
    mem = [
        {"address": 0x42000, "symbolic": True, "size": 2},
        {"address": 0x42002, "symbolic": True, "size": 2},
    ]
    a, _, sa = fixture(tmp_path, "a10020", memory=mem)
    b, _, sb = fixture(tmp_path, "a10220", name="b", memory=mem)
    r = compare(a, b, sa, sb, ["ax"])
    assert r["status"] == "DIFFERENT"
    assert r["replay"]["left"]["events"][0]["address"] == 0x42000
    assert r["replay"]["right"]["events"][0]["address"] == 0x42002


def test_distinct_segment_offsets_alias(tmp_path):
    regs = {
        "cs": 0x1000,
        "ds": 0x4000,
        "ss": 0x4001,
        "es": 0xA000,
        "sp": 0x8000,
        "bp": 0xF0,
    }
    mem = [{"address": 0x40100, "symbolic": True, "size": 2}]
    a, _, sa = fixture(tmp_path, "a100018b5600", memory=mem, registers=regs)
    b, _, sb = fixture(tmp_path, "a1000189c2", name="b", memory=mem, registers=regs)
    assert compare(a, b, sa, sb, ["ax", "dx"])["status"] == "EQUIVALENT_WITHIN_MODEL"
    # An event difference remains visible when ordered reads are observable.
    assert compare(a, b, sa, sb, ["ax", "dx"], effects=True)["status"] == "DIFFERENT"


def test_changed_branch(tmp_path):
    a, _, sa = fixture(tmp_path, "83f8007403b80100", claims=[preserved()])
    b, _, sb = fixture(tmp_path, "83f8007503b80100", name="b")
    assert compare(a, b, sa, sb, ["ax"])["status"] == "DIFFERENT"


def test_amd64_backend_and_replay(tmp_path):
    a, _, sa = fixture(tmp_path, "488d4701", arch="AMD64")
    b, _, sb = fixture(tmp_path, "488d4702", arch="AMD64", name="b")
    r = compare(a, b, sa, sb, ["rax"])
    assert r["status"] == "DIFFERENT"
    assert r["left"]["adapter"] == "angr-vex"


def test_loop_limit_is_inconclusive(tmp_path):
    a, _, sa = fixture(tmp_path, "ebfe", claims=[preserved()], limits={"steps": 3})
    r = query(a, sa)
    assert not r["complete"] and r["claims"][0]["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("code", ["cd21", "cb", "9a00100020", "26a10020"])
def test_unsupported_machine_operations(tmp_path, code):
    a, _, sa = fixture(tmp_path, code, claims=[preserved()])
    r = query(a, sa)
    assert not r["complete"] and r["issues"][0]["kind"] == "UNSUPPORTED"


def test_unknown_call_never_stubbed(tmp_path):
    a, _, sa = fixture(tmp_path, "e81000", claims=[preserved()])
    r = query(a, sa)
    assert not r["complete"]
    assert "unknown call/target" in r["issues"][0]["reason"]


def test_symbolic_indirect_control_is_incomplete(tmp_path):
    a, _, sa = fixture(tmp_path, "ffe3", claims=[preserved()])
    r = query(a, sa)
    assert not r["complete"] and "indirect" in r["issues"][0]["reason"]


def test_symbolic_address_limit_never_chooses_one(tmp_path):
    a, _, sa = fixture(tmp_path, "8a07", claims=[preserved()], limits={"addresses": 2})
    r = query(a, sa)
    assert not r["complete"] and r["claims"][0]["status"] == "INCONCLUSIVE"


def test_exhaustive_small_symbolic_address_domain(tmp_path):
    a, _, sa = fixture(
        tmp_path,
        "8a07",
        claims=[preserved()],
        memory=[{"address": 0x40000, "size": 4, "symbolic": True}],
    )
    sa["registers"]["bx"] = {"symbolic": True, "min": 0, "max": 3}
    r = query(a, sa)
    assert r["complete"] and r["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"


def test_missing_memory_not_zero_filled(tmp_path):
    a, _, sa = fixture(tmp_path, "a10020", claims=[preserved()])
    r = query(a, sa)
    assert not r["complete"] and "initialized" in r["issues"][0]["reason"]


@pytest.mark.parametrize("instruction", [0x11001, 0x12000, 0x11000])
def test_invalid_read_claim_cannot_vacuously_pass(tmp_path, instruction):
    a, _, sa = fixture(
        tmp_path, "b80000", claims=[{"kind": "no_read", "instruction": instruction}]
    )
    with pytest.raises(Invalid):
        query(a, sa)


def test_overlapping_code_rejected(tmp_path):
    _, config, spec = fixture(tmp_path, "9090")
    spec["code"].append({"address": 0x11001, "size": 1})
    config.write_text(json.dumps(spec))
    with pytest.raises(Invalid, match="Overlapping code"):
        contract(config)


def test_a20_disabled_explicitly_unsupported(tmp_path):
    a, _, sa = fixture(tmp_path, "90", a20=False)
    with pytest.raises(Unsupported, match="A20"):
        Analysis(a, sa)


def test_write_code_rejected(tmp_path):
    a, _, sa = fixture(tmp_path, "a30010", claims=[preserved()])
    sa["registers"]["ds"] = 0x1000
    r = query(a, sa)
    assert not r["complete"] and "selected code" in r["issues"][0]["reason"]


def test_cli_json_exit_codes(tmp_path):
    a, config, _ = fixture(tmp_path, "90", claims=[preserved()])
    run = subprocess.run(
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
    assert run.returncode == 0
    assert json.loads(run.stdout)["claims"][0]["status"] == "ESTABLISHED_WITHIN_MODEL"
    a.write_bytes(bytes.fromhex("cd21"))
    run = subprocess.run(
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
    assert run.returncode == 3 and json.loads(run.stdout)["status"] == "INVALID"


def test_unrelated_elf_objects_c_and_cpp(tmp_path):
    import cle
    import shutil

    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("clang not available for the separate ELF fixture")
    sources = [
        (
            "a.c",
            "unsigned long add_one(unsigned long x){return x+1;}\nunsigned long neighbor(unsigned long x){return x+99;}\n",
        ),
        ("b.cpp", 'extern "C" unsigned long add_one(unsigned long x){return 1+x;}\n'),
        ("c.c", "unsigned long add_one(unsigned long x){return x+2;}\n"),
    ]
    cases = []
    for name, code in sources:
        src = tmp_path / name
        src.write_text(code)
        obj = src.with_suffix(".o")
        subprocess.run(
            [
                compiler,
                "--target=x86_64-unknown-linux-gnu",
                "-O2",
                "-ffreestanding",
                "-c",
                str(src),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
        )
        symbol = cle.Loader(str(obj), auto_load_libs=False).main_object.get_symbol(
            "add_one"
        )
        spec = {
            "schema": 1,
            "format": "auto",
            "architecture": "AMD64",
            "entry": symbol.rebased_addr,
            "code": [{"address": symbol.rebased_addr, "size": symbol.size}],
            "stops": [{"address": 0x900000, "kind": "return"}],
            "registers": {"rsp": 0x800000},
            "flags": 0x202,
            "memory": [
                {"address": 0x800000, "hex": (0x900000).to_bytes(8, "little").hex()}
            ],
        }
        config = src.with_suffix(".json")
        config.write_text(json.dumps(spec))
        cases.append((obj, config, contract(config)[0]))
    a, b, c = cases
    assert (
        compare(a[0], b[0], a[2], b[2], ["rax"])["status"] == "EQUIVALENT_WITHIN_MODEL"
    )
    assert compare(a[0], c[0], a[2], c[2], ["rax"])["status"] == "DIFFERENT"
    view = subprocess.run(
        [
            sys.executable,
            "-m",
            "binquery",
            "inspect",
            str(a[0]),
            "--symbol",
            "add_one",
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    result = json.loads(view.stdout)
    assert view.returncode == 0 and result["selected_size"] == a[2]["code"][0]["size"]
    assert result["decoded_bytes"] == result["selected_size"]
    assert result["instructions"][-1]["instruction"].startswith("ret")
    a[2]["code"][0]["sha256"] = "0" * 64
    with pytest.raises(Invalid, match="SHA256"):
        compare(a[0], a[0], a[2], a[2], ["rax"])


@pytest.mark.parametrize(
    "code,arch",
    [
        ("8ec8", "x86:LE:16:Real Mode"),  # invalid MOV CS, AX
        ("0f20c0", "x86:LE:16:Real Mode"),  # CR0 has no declared semantics
        ("8ed0", "x86:LE:16:Real Mode"),  # MOV SS changes machine state
        ("0f20c0", "AMD64"),
        ("65488b00", "AMD64"),  # GS base requires runtime state
    ],
)
def test_instruction_forms_outside_qualified_state(tmp_path, code, arch):
    a, _, spec = fixture(
        tmp_path,
        code,
        arch=arch,
        claims=[preserved("rsi" if arch == "AMD64" else "si")],
    )
    r = query(a, spec)
    assert not r["complete"] and r["issues"][0]["kind"] == "UNSUPPORTED"
    assert r["claims"][0]["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("arch", ["AMD64", "x86:LE:16:Real Mode"])
@pytest.mark.parametrize("flags", [0x302, 0x20202, 0x202 & ~2])
def test_unmodeled_execution_flags_rejected(tmp_path, arch, flags):
    with pytest.raises(Unsupported, match="Flags"):
        fixture(tmp_path, "90", arch=arch, flags=flags)


def test_noncanonical_amd64_memory_cannot_establish(tmp_path):
    a, _, spec = fixture(
        tmp_path,
        "488b00",
        arch="AMD64",
        claims=[preserved("rsi")],
        registers={"rsp": 0x700000, "rax": 1 << 47},
        memory=[{"address": 1 << 47, "hex": "0000000000000000"}],
    )
    with pytest.raises(Unsupported, match="Initial memory"):
        query(a, spec)


@pytest.mark.parametrize(
    "arch,address,raw",
    [
        ("AMD64", (1 << 64) + 0x400000, "00"),
        ("AMD64", (1 << 47) - 1, "0000"),
        ("x86:LE:16:Real Mode", 0x110000, "00"),
        ("x86:LE:16:Real Mode", 0x10FFFF, "0000"),
    ],
)
def test_unused_memory_still_requires_valid_address_span(tmp_path, arch, address, raw):
    a, _, spec = fixture(
        tmp_path,
        "90",
        arch=arch,
        claims=[preserved("rsi" if arch == "AMD64" else "si")],
        memory=[{"address": address, "hex": raw}],
    )
    with pytest.raises(Unsupported, match="Initial memory"):
        query(a, spec)


@pytest.mark.parametrize(
    "change",
    [
        "concrete_register",
        "missing_register",
        "wide_register",
        "flags",
        "bounded_memory",
        "concrete_memory",
        "extra_memory",
    ],
)
def test_replay_rejects_witness_outside_contract(tmp_path, change):
    from binquery.replay import replay

    a, _, spec = fixture(
        tmp_path,
        "40",
        claims=[preserved("ax")],
        memory=[
            {"address": 0x40000, "symbolic": True, "size": 1, "min": 0, "max": 3},
            {"address": 0x40001, "hex": "23"},
        ],
    )
    spec["registers"]["ax"] = 0
    result = query(a, spec)
    w = copy.deepcopy(result["claims"][0]["witness"])
    assert result["claims"][0]["replay"]["matched"]
    if change == "concrete_register":
        w["registers"]["ax"], w["expected"]["registers"]["ax"] = 10, 11
    elif change == "missing_register":
        del w["registers"]["bx"]
    elif change == "wide_register":
        w["registers"]["bx"] = 65536
    elif change == "flags":
        w["flags"] ^= 1
    elif change == "bounded_memory":
        w["memory"][0]["hex"] = "04"
    elif change == "concrete_memory":
        w["memory"][1]["hex"] = "24"
    else:
        w["memory"].append({"address": 0x50000, "hex": "00"})
    with pytest.raises(Invalid):
        replay(Analysis(a, spec), w)


def test_real_memory_read_modify_write_replays(tmp_path):
    a, _, spec = fixture(
        tmp_path,
        "fe07",
        memory=[{"address": 0x40000, "symbolic": True, "size": 1}],
        claims=[{"kind": "no_read", "instruction": 0x11000}],
    )
    spec["registers"]["bx"] = 0
    r = query(a, spec)
    assert r["complete"] and r["claims"][0]["status"] == "REFUTED"
    assert r["claims"][0]["replay"]["matched"]
    assert [e["kind"] for e in r["claims"][0]["replay"]["events"]] == ["read", "write"]
