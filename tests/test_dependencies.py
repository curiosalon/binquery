import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


spec = importlib.util.spec_from_file_location(
    "check_dependencies",
    Path(__file__).resolve().parents[1] / "tools/check_dependencies.py",
)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


@pytest.mark.parametrize(
    "system,version,text,stderr,expected",
    [
        (
            "darwin",
            "5.1.0.0",
            "z3-solver 5.1.0.0 is not supported on this platform",
            "",
            True,
        ),
        (
            "linux",
            "5.1.0.0",
            "z3-solver 5.1.0.0 is not supported on this platform",
            "",
            False,
        ),
        (
            "darwin",
            "5.1.0.1",
            "z3-solver 5.1.0.0 is not supported on this platform",
            "",
            False,
        ),
        (
            "darwin",
            "5.1.0.0",
            "z3-solver 5.1.0.0 is not supported on this platform\nmissing dependency",
            "",
            False,
        ),
        (
            "darwin",
            "5.1.0.0",
            "z3-solver 5.1.0.0 is not supported on this platform",
            "error",
            False,
        ),
    ],
)
def test_only_known_dependency_metadata_warning_is_excepted(
    monkeypatch, system, version, text, stderr, expected
):
    monkeypatch.setattr(checks.sys, "platform", system)
    monkeypatch.setattr(checks.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(checks.platform, "mac_ver", lambda: ("27.0.1", (), "arm64"))
    dist = SimpleNamespace(
        version=version, read_text=lambda name: "Tag: py3-none-macosx_13_3_arm64\n"
    )
    monkeypatch.setattr(checks.importlib.metadata, "distribution", lambda name: dist)
    result = SimpleNamespace(returncode=1, stdout=text, stderr=stderr)
    assert checks.known_z3_tag_warning(result) is expected


def test_wrong_cpu_wheel_is_not_excepted(monkeypatch):
    monkeypatch.setattr(checks.sys, "platform", "darwin")
    monkeypatch.setattr(checks.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(checks.platform, "mac_ver", lambda: ("27.0.1", (), "arm64"))
    dist = SimpleNamespace(
        version="5.1.0.0", read_text=lambda name: "Tag: py3-none-macosx_13_3_x86_64\n"
    )
    monkeypatch.setattr(checks.importlib.metadata, "distribution", lambda name: dist)
    done = SimpleNamespace(
        returncode=1,
        stdout="z3-solver 5.1.0.0 is not supported on this platform",
        stderr="",
    )
    assert not checks.known_z3_tag_warning(done)
