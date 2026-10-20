# binquery

binquery compares what two pieces of machine code do. Give it two binaries,
describe their inputs, and choose what to compare: return values, registers, memory contents,
or the order of reads and writes. It either establishes agreement across the
inputs you described or finds an input that makes the code behave differently.

This is useful when checking a replacement for an old routine, investigating
a compiler optimization, or testing your understanding of unfamiliar assembly.
The code can come from C, C++, Pascal, or assembly; binquery works on the compiled
instructions.

## Install

You need Python 3.12 or later and Git. On Linux or macOS:

```sh
git clone https://github.com/curiosalon/binquery.git
cd binquery
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
binquery --help
```

On Windows, run these commands in PowerShell:

```powershell
git clone https://github.com/curiosalon/binquery.git
cd binquery
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\binquery.exe --help
```

For the examples below, Windows users can replace `python` with
`.\.venv\Scripts\python.exe` and `binquery` with
`.\.venv\Scripts\binquery.exe`. Run the examples from the repository directory.

## Try it: two ways to add one

The repository includes two tiny 16-bit x86 binaries:

```asm
; examples/inc.bin
inc ax

; examples/add.bin
add ax, 1
```

AX is a 16-bit CPU register. Both instructions add one to it. Ask binquery to
compare the resulting AX values:

```sh
binquery compare examples/inc.bin examples/add.bin --contract examples/inc.json --right-contract examples/add.json --observe ax
```

The result is `EQUIVALENT_WITHIN_MODEL`. The JSON contracts describe where the
code runs and its initial machine state. They leave AX free to take any of its
65,536 possible values, so this comparison covers all of them.

Now include the carry flag, CF:

```sh
binquery compare examples/inc.bin examples/add.bin --contract examples/inc.json --right-contract examples/add.json --observe ax --observe cf
```

The result is `DIFFERENT`. With AX initially `0xffff`, both instructions produce
zero, but `ADD` sets carry while `INC` leaves it unchanged. The contracts start
with carry clear. binquery finds that input and checks it with a CPU emulator.

That is the central idea: ask a specific question about the behavior you need
to preserve, then let the solver look for a case that breaks it.

## Learn by doing

- [Packed bits, memory reads, and counterexamples](docs/CAPABILITIES.md):
  extract three bits from a word, catch a wrong mask, and examine a wider read.
- [Compare compiled C and C++ functions](docs/COMPILED.md):
  compile ordinary source files and compare the resulting object code.
- [Contract and command reference](docs/REFERENCE.md):
  describe your own inputs, choose outputs, save results, and replay a difference.
- [Build, test, and contribute](docs/BUILDING.md):
  source packages, wheels, development setup, and platform checks.

## How it works

angr executes the instructions with symbolic inputs. A symbolic input stands
for a range of values rather than one test case. A constraint solver then
looks for values that would make the selected outputs disagree. When it finds
a difference, binquery runs that concrete input through Unicorn, a separate
CPU emulator, to check the result.

Execution supports a scalar subset of AMD64 and 16-bit x86 real mode.
Start with a small routine whose inputs and memory layout you understand.
The [reference](docs/REFERENCE.md#supported-code) lists the supported operations.

Human-readable output is the default. Add `--json` to save or process results:

```sh
binquery compare examples/inc.bin examples/add.bin --contract examples/inc.json --right-contract examples/add.json --observe ax --observe cf --json > difference.json
```

Like `diff`, a comparison exits with code **0** for agreement and **1** for a
difference. Code **2** means the analysis could not finish or encountered an
unsupported operation; **3** means invalid input and **4** means a tool error.

## License

Copyright (c) 2026 Curio Salon

Written under the direction of Curio Salon using the GPT-6 Astra model.

Distributed under the [ISC license](LICENSE).
