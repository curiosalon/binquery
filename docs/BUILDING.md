# Build, test, and contribute

binquery uses Python's standard packaging tools: pip for installation and
setuptools for source archives and wheels. Use Python 3.12 or later.

## Development setup

On Linux or macOS:

```sh
git clone https://github.com/curiosalon/binquery.git
cd binquery
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q -ra
python tools/check_examples.py
```

On Windows PowerShell, activation is optional:

```powershell
git clone https://github.com/curiosalon/binquery.git
cd binquery
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q -ra
.\.venv\Scripts\python.exe tools/check_examples.py
```

An editable install makes source changes available immediately. The `dev` extra
adds pytest, build, twine, and Ruff. Clang is optional; it enables the compiled
C/C++ examples and their tests.

## Build a package

Using the Python executable from your environment:

```sh
python -m build
python -m twine check dist/*
```

This creates a source archive and a wheel in `dist/`. The build produces the
wheel from the source archive, checking that the archive contains the required
files. The source archive also includes the tutorials, examples, and tests.

Install a wheel in another environment with:

```sh
python -m pip install /path/to/binquery-0.5.0-py3-none-any.whl
```

Replace the path with your built wheel. pip installs the native dependencies
for the destination platform. Current installation is from Git or a built
wheel; there is no binquery release on PyPI.

## Checks before a pull request

```sh
python -m ruff format --check src tests tools examples
python tools/check_dependencies.py
python -m pytest -q -ra
python tools/smoke.py
python tools/check_examples.py
```

Run `python -m ruff format src tests tools examples` to apply formatting.
`tools/smoke.py` exercises the installed CLI outside the checkout.
`tools/check_examples.py` runs the tutorial comparisons and checks the expected
results, including the intentional differences. It reports a skip for the
compiled examples if Clang is unavailable.

For a bug report, include `binquery --version`, the command, its JSON result,
and a small binary and contract that reproduce the problem. For instruction
support changes, add both a successful case and a case that should fail; check
concrete counterexamples with Unicorn.

## Platforms and dependencies

The [CI workflow](https://github.com/curiosalon/binquery/actions/workflows/ci.yml)
builds and installs the package on Linux, macOS, and Windows with Python 3.12,
and on Linux with Python 3.13 and 3.14. Each job runs the test suite and CLI
examples. The workflow page has the results and downloadable packages.

Runtime dependencies are declared in `pyproject.toml`: angr, archinfo, CLE,
Capstone, pypcode, and Unicorn. Their versions are pinned because changes to
instruction semantics can affect analysis results. pip resolves their
platform-specific dependencies normally.

On a system without compatible native wheels, use the upstream build
instructions for [angr](https://docs.angr.io/en/latest/getting-started/installing.html),
[pypcode](https://pypi.org/project/pypcode/4.0.1/), and
[Unicorn](https://pypi.org/project/unicorn/2.1.4/). Those builds may require
a C/C++ compiler and additional libraries.

### Z3 warning on macOS

The pinned Z3 5.1.0.0 wheel has inconsistent macOS version tags. On macOS 13.3
or later, `pip check` can report it as unsupported even though it runs.
`tools/check_dependencies.py` recognizes that exact warning for the matching
CPU architecture and still rejects other dependency errors.
