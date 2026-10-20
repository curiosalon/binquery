# Building and testing

binquery is a Python package built with setuptools through the standard
PEP 517 interface. Install CPython 3.12 or later. Dependencies are available
through public PyPI packages. Native dependency wheels must be available
for that Python and host combination, or their build requirements must be
installed separately.

## Linux and macOS

```sh
git clone https://github.com/curiosalon/binquery.git
cd binquery
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ".[dev]"
python -m build
python -m twine check dist/*
python -m pytest -q -ra
python tools/smoke.py
```

## Windows PowerShell

Activation is optional; these commands do not require changing execution policy.

```powershell
git clone https://github.com/curiosalon/binquery.git
cd binquery
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install ".[dev]"
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe -m twine check dist/*
.\.venv\Scripts\python.exe -m pytest -q -ra
.\.venv\Scripts\python.exe tools/smoke.py
.\.venv\Scripts\binquery.exe --help
```

`python -m build` produces a source archive and a wheel under `dist/`,
building the wheel from the source archive. Install the wheel with
`python -m pip install /path/to/binquery-0.5.0-py3-none-any.whl`.
The wheel contains Python code; pip installs the platform-specific native
dependencies separately. A portable wheel is not a claim of support for
every host architecture.

## Dependencies and reproducibility

`pyproject.toml` is the maintained dependency declaration. Runtime packages
come from PyPI: angr, archinfo, CLE, Capstone, pypcode and Unicorn. The
semantic backends are pinned because the adapter depends on their tested
behavior. The optional `dev` extra adds pytest, build, twine and Ruff.
Normal installation resolves platform markers and transitive dependencies
through pip, without a host-specific environment freeze.

If wheels are unavailable, follow the upstream instructions rather than
assuming binquery's pure Python build also compiles its dependencies:
[angr installation](https://docs.angr.io/en/latest/getting-started/installing.html),
[pypcode](https://pypi.org/project/pypcode/4.0.1/),
[Unicorn](https://pypi.org/project/unicorn/2.1.4/).
Their source builds may need native compiler toolchains. OpenBSD, Windows
ARM64 and other untested hosts are not presently qualified.

## Validation

GitHub Actions builds and installs the wheel, runs tests and executes
synthetic CLI examples on Linux, macOS and Windows with Python 3.12, plus
Linux with Python 3.13 and 3.14. Consult the actual workflow results for
platform qualification; a configured job alone is not a passing test.
The CLI deadline uses a separate Python analysis process with a portable
timeout. It kills and reaps that process on expiry and returns INCONCLUSIVE.
Neither process launches the input executable.

Tests construct synthetic machine code. The separate C/C++ ELF test uses
clang when available and reports a skip otherwise. All distributed test inputs
are synthetic; original game binaries and proprietary toolchains are not
required or included.

Run `python -m ruff format --check src tests tools` to verify the formatting.
The build produces local artifacts and does not upload them to PyPI.

## Known upstream macOS packaging warning

The pinned public Z3 5.1.0.0 wheel has a `macosx_13_0` filename but an internal
`macosx_13_3` WHEEL tag. On tested macOS this installs and runs, while `pip check`
reports it as unsupported. `python tools/check_dependencies.py` retains pip's
checks and reports a narrow exception only for that exact warning, version and
internal tag matching the running architecture on macOS 13.3 or later. Every other missing, conflicting or
unsupported dependency fails. No installed metadata is patched. The full tests
and installed CLI smoke checks remain required; this exception is not runtime
qualification. Other operating systems use pip's result unchanged.
