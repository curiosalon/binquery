# binquery

A standalone Unix command for bounded machine code questions. Inputs are ordinary
files and explicit machine contracts. There is no compiler invocation, application
registry, background service or runtime orchestration dependency in the tool.

This is a qualified prototype, not an unrestricted equivalence prover. It accepts
caller supplied binaries; support is explicit rather than implying every format,
instruction, ABI or runtime works.

Copyright (c) 2026 Curio Salon

Written under the direction of Curio Salon using the GPT-6 Astra model.
Licensed under the [OpenBSD ISC wording](LICENSE).

Read the [capability and bitfield investigation summary](docs/CAPABILITIES.md)
for an explanation of what the results establish.

## Install and run

Use CPython 3.12 or later in an isolated environment. Clone this repository,
then install with ordinary pip dependencies:

```sh
git clone https://github.com/curiosalon/binquery.git
cd binquery
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
binquery --help
```

On Windows, use `py -3.12 -m venv .venv` and
`.\\.venv\\Scripts\\python.exe -m pip install .`, then run
`.\\.venv\\Scripts\\binquery.exe --help`.
See [Building and testing](docs/BUILDING.md) for PowerShell commands,
wheel/source builds, dependency details and host qualification.

`python -m pip install ".[dev]"` adds build and test tools;
`python -m build` creates a wheel and source archive. No game installation,
proprietary compiler, Ghidra installation, API key or model service is needed.
Native backend dependencies come from PyPI and retain their own licenses.
Installation is currently from Git or a built wheel, not a claimed PyPI release.

The command can run from any working directory. Auxiliary input paths
resolve relative to the contract file. The proof engines are angr
10.0.4.post1, pypcode 4.0.1 and Unicorn 2.1.4; the tested semantic dependencies
are pinned in `pyproject.toml`. Platform-specific transitive dependencies resolve through pip.

```sh
binquery inspect program.o --symbol add_one --json
binquery inspect code.bin --format blob --arch 'x86:LE:16:Real Mode' --base 0x11000
binquery query code.bin --contract function.json --json > result.json
binquery replay code.bin --contract function.json --witness result.json --claim 1 --json
binquery compare old.bin new.bin --contract old.json --right-contract new.json --observe ax --json
binquery schema --json
binquery schema --kind comparison --schema-only
binquery example --kind layout --json
binquery example --arch real16 --json
```

Contract discovery is native to the installed command. `binquery schema
--schema-only` emits a standalone JSON Schema; execution still validates numeric
bounds, machine state, code identities and supported instructions. The examples
are explicitly synthetic, with one NOP and a boundary stop. To run one:

```sh
binquery example --arch AMD64 --contract-only > model.json
printf '\220' > nop.bin
binquery query nop.bin --contract model.json --json
```

The example command does not inspect your binary or infer its initial state.
Change the contract for the actual function and its ABI before using it there.

Human output is the default. `--json` writes a schema-versioned result to stdout;
library diagnostics go to stderr. Shell redirection works normally. Exit codes:
0 established/equivalent/inspected/replayed; 1 refuted/different; 2 incomplete or
unsupported; 3 invalid input; 4 internal tool error. For multiple claims, an
incomplete result takes precedence over a refuted one in the process exit code.
Every individual result remains visible in JSON. No target host process runs:
symbolic execution uses angr and concrete witness execution uses Unicorn.

## A runnable independent example

The supplied examples contain one 16 bit INC instruction and an ADD instruction.
Both calculate AX+1 modulo 65536. INC preserves carry; ADD updates carry.

```sh
binquery compare examples/inc.bin examples/add.bin --contract examples/inc.json --right-contract examples/add.json --observe ax --json
binquery compare examples/inc.bin examples/add.bin --contract examples/inc.json --right-contract examples/add.json --observe ax --observe cf --json
```

The first reports EQUIVALENT_WITHIN_MODEL for the declared AX and exit-kind
observations. The second reports DIFFERENT with AX initially FFFF and an
independently replayed carry difference. This is why observables are explicit.

## Input contract

Schema 1 has these fields:

| Field | Meaning |
| --- | --- |
| format | blob (default) or auto (CLE executable/object loader) |
| architecture | AMD64 or x86:LE:16:Real Mode for execution; raw inputs require it |
| entry | Physical address for real mode; loaded virtual address for AMD64 |
| code | Explicit nonoverlapping ranges: address and size, optional raw file offset, auxiliary file and whole-file sha256 |
| stops | Explicit outside-code addresses with kind return, failure or boundary |
| registers | Initial concrete values or symbolic unsigned bounds; unlisted general registers are unconstrained |
| flags | Explicit initial arithmetic/IF/DF flags; reserved bit 1 set; trap, mode and privilege flags reject |
| memory | Nonoverlapping concrete hex bytes or symbolic ranges, with optional unsigned scalar bounds |
| claims | preserved register, return_equals register/value, or no_read at a decoded memory-reading instruction |
| limits | steps per path, pending+terminal states, seconds, solver_ms and addresses per symbolic memory access |
| a20 | true only in the qualified real mode profile |
| shift_count | real16: portable (default) requires raw counts 0..31; masked5 explicitly selects five bit count masking |

Integers may be JSON numbers or strings such as "0x11000". Real mode requires
concrete CS, DS, SS, ES and SP. Near-only code and stops share CS. Unknown fields,
overlapping code/memory, invalid read sites and inconsistent bounds reject.
For `auto`, code ranges are loaded virtual addresses, without raw file offsets
or auxiliary files. Object symbols can help select a range; the tool never treats
the first RET as a function boundary. `inspect --symbol` uses the symbol extent;
when absent, supply an explicit size. Shared tails can be separate code ranges,
but automatic discovery and correspondence are outside this prototype.

Example memory declarations:

```json
[
  {"address": "0x78000", "hex": "00f1"},
  {"address": "0x78002", "symbolic": true, "size": 2, "min": 0, "max": 3}
]
```

The first supplies a little endian near return offset. The second is an unsigned
16 bit stack input. Bytes themselves are named consistently by address, preserving
aliases. Memory scalar bounds are little endian. Reads must refer to supplied
memory, selected code or bytes already written by execution. Unknown initial
memory does not silently become zero. No implicit external call summary is admitted.
Saved witnesses must satisfy the same declared input domain before replay. Code
hash pins apply to the entire input file in both raw and automatic loader modes.

## Meaning of results

* ESTABLISHED_WITHIN_MODEL: the property has no violation on all completed paths
  in the supplied domain, within the qualified instruction/model semantics.
* REFUTED: a solver model violates the property and its registers, instruction
  path, stop and ordered memory accesses agree with independent Unicorn replay.
* EQUIVALENT_WITHIN_MODEL: paired path analysis found no difference in the
  explicitly requested registers, exit kind, final RAM regions, near pointer
  observations and optionally ordered memory effects.
  It is not a statement about undeclared outputs or portable source semantics.
* DIFFERENT: the declared paired difference is independently replayed.
* INCONCLUSIVE or UNSUPPORTED: no proof claim; the result includes the limit or
  unsupported operation. INVALID reports an input contract error.

Preservation applies at every declared stop. `return_equals` applies only to
stops marked return. An unreachable but correctly decoded `no_read` site is
reported as not reached, and is distinct from an invalid instruction address.
Replayed witnesses validate those executions; they do not universally validate
SLEIGH, angr or an UNSAT result.

By default, paired comparison requires identical declared initial registers,
flags and memory. Code ranges and stop addresses may differ. Version 0.4 adds
an explicit bounded real16 layout relation, described below; it never infers
correspondence or rewrites either image. `byte_match` is
literal equality of selected ranges, not a relocation-normalized instruction
claim. A differently encoded arithmetic sequence can therefore have byte_match
false and EQUIVALENT_WITHIN_MODEL true.

Only finite address sets are exhaustively enumerated. There is no fallback to one
chosen symbolic address. A limit, timeout, unknown call, unresolved indirect target
or incomplete path prevents establishment/equivalence. The CLI enforces a wall
deadline in addition to solver and exploration limits.

## Final memory and explicit layout correspondence

Select final ordinary RAM independently of ordered reads/writes:

```sh
binquery compare old.bin new.bin --contract old.json --right-contract new.json --observe-memory 0x40100:4 --json
```

Repeat `--observe-memory ADDRESS:SIZE` for multiple regions at the same addresses.
For named regions or different addresses, use `--comparison comparison.json`:

```json
{
  "schema": 1,
  "memory": [{"name": "result", "left": "0x40100", "right": "0x40200", "size": 4}],
  "pointers": [{"register": "ax", "segment": "ds", "region": "result"}],
  "relation": {
    "regions": [{"name": "result", "left": "0x40100", "right": "0x40200", "size": 4}],
    "stack": {"address": "0x77f00", "size": "0x200"},
    "pointers": []
  }
}
```

This example presumes each machine contract declares that four-byte initial RAM
row with the same scalar/byte domain, SS=0x7000 and SP within the stack window.
Add a relation row for **every** other initial memory row, including stack inputs.
The top-level `pointers` are output observations. `relation.pointers` describe
input pointers; omitting an input pointer leaves that register a raw equal scalar.
Each pointer names the same register and segment on both sides. Its physical
address must stay inside the named region, and the relation equates its byte
offset within that region. Input pointers may have bounded symbolic offsets.

`comparisons` reports separate verdicts for each selected aspect. Adding
`--effects` can report `final_memory: EQUIVALENT_WITHIN_MODEL` together with
`ordered_memory_effects: DIFFERENT`. The overall result is DIFFERENT if any
aspect has a replayed counterexample. Final memory differences identify exact
byte offsets and retain both native final byte strings. Raw `--observe ax` is
still a numeric comparison, even when AX is also a related pointer observable.
`byte_match` always compares the selected unmodified code bytes.

Only the declared output regions are proved equal. The result lists unobserved
registers/flags, states that all other memory is unproved, and reports completed
path write sites outside the final regions (with explicit truncation at 64 sites).
Include relevant neighbors and aliases yourself. Final observations add no
execution read events. A selected byte must be initialized or written on every
completed path; inaccessible final bytes do not silently become zero.

The initial relation is deliberately narrow:

* At most 64 named regions and 4096 bytes total, with disjoint extents per side.
  Final observations have the same independent bounds. Overlapping aliases must
  share one region; separate names cannot disguise overlapping physical bytes.
* Every mapped region matches one complete initial RAM declaration. The two
  declarations have identical concrete bytes or symbolic scalar bounds. Domains
  are not silently intersected. Distinct per-side symbols and explicit relations
  preserve corresponding bytes even when physical addresses are permuted.
* Only real16 with equal, unchanged CS/DS/ES/SS and equal initial SP. The optional
  fixed stack window lies within SS and contains SP throughout execution. Without
  it, the entire SS segment is protected. DS and SS may alias when a bounded
  window keeps moved data disjoint from stack storage. Stack rows stay at their
  original addresses; accesses outside named RAM or that window reject.
* Declared input and output near pointers use general 16 bit registers through
  DS/ES. Input offset domains must match exactly and preserve possible aliases.
  Raw zero, one-past, stack/code targets and domains not proved inside one named
  region reject. Changing segments or pointer register roles across sides,
  embedded pointer translation, far pointers, object graphs and general pointer
  equivalence are unsupported. Unmarked bytes/registers are raw data, not inferred
  pointers. The caller is responsible for selecting the intended relationship.
* Final related RAM must select corresponding offsets of mapped regions. Raw
  ordered effects remain available and are **not** relocated or normalized by
  the relation. No MMIO, volatile-interaction or physical bus claim is made.

Native runnable bundles include all synthetic binary bytes and JSON inputs:

```sh
binquery example --kind final-memory --json > example.json
# Or: binquery example --kind layout --json > example.json
python3 - <<'PYEXAMPLE'
import json
from pathlib import Path
for name, row in json.loads(Path("example.json").read_text())["files"].items():
    Path(name).write_bytes(bytes.fromhex(row["hex"]) if "hex" in row else json.dumps(row["json"]).encode())
PYEXAMPLE
binquery compare left.bin right.bin --contract left.json --right-contract right.json --comparison comparison.json --effects --json > difference.json
binquery replay left.bin --contract left.json --witness difference.json --side left --aspect ordered_memory_effects --json
binquery replay right.bin --contract right.json --witness difference.json --side right --aspect ordered_memory_effects --json
```

A saved comparison replay validates one concrete execution, including final
bytes. It does not re-establish paired equivalence or infer the relationship.
Both native examples produce functional equivalence and a raw access difference.
The comparison schema is available through `schema --kind comparison` and the
execution commands' `--help` describes these options.

## Qualified scope and adapter boundary

The code uses angr's p-code engine for the real mode profile and its VEX engine
for AMD64. Current instruction admission is a conservative scalar subset:
MOV variants, LEA, ADD/SUB/CMP/INC/DEC, AND/OR/XOR, PUSH/POP, near CALL/RET,
JMP, ordinary conditional branches and NOP. The real16 profile also admits
CLD/STD, TEST, NOT, unsigned MUL and SHL/SHR with immediate or CL counts.
Concrete near indirect control must
resolve uniquely inside supplied code or to a declared stop. Every instruction
family is not exhaustively ISA verified; supported proof fixtures and negative
controls are documented separately.
Operand registers and forms are checked as well as mnemonics. Real16 MOV/POP
may update DS/ES only when each resulting segment has one possible value.
Other segment writes, control/debug registers and legacy prefixes reject;
AMD64 REX is supported.
AMD64 addresses are restricted to the lower canonical range. Real mode byte and
word memory INC/DEC/ADD/SUB/AND/OR/XOR/NOT/SHL/SHR are supported for ordinary
RAM. SLEIGH's
repeated operand/flag loads are normalized only after proving one read/write
location and width, identical prewrite values and the exact stored postwrite
value. Unexpected effect shapes reject. This normalization changes reported
memory effects only.

The real16 flag adapter tracks whether CF/PF/ZF/SF/OF remain defined. A branch or
observation that could depend on an undefined flag returns UNSUPPORTED. MUL
qualifies CF/OF; shifts qualify flags according to their count, preserving prior
flag definedness at count zero. AF is not an observable. The pinned SLEIGH SHR
implementation needs a generic OF correction at counts zero and one, tested
against independent Unicorn replay. This is separate from memory normalization.

The default `shift_count: "portable"` rejects any feasible raw count above 31.
`"masked5"` explicitly selects the 286 and later count rule. Neither setting
qualifies an entire historical CPU or 8086 unmasked counts above 31. Paired
contracts must select the same rule. Saved replay inputs obey the same limit.

The small realmode.py adapter addresses three observed upstream gaps:

1. Physical addresses require 32 bits even though instruction mode is 16 bits.
2. SLEIGH's segment user operation needs explicit real mode translation.
3. SLEIGH temporary storage needs byte-addressable subrange reads and writes.

It contains no application addresses, compiler frame recognition or service stubs.
Actual supplied helper bytes execute normally. Near frames and nonzero segment
aliasing are tested. A20 disabled, far calls/returns, interrupts, device access,
unqualified prefixes/instructions, self modifying code, unrestricted symbolic
addresses and unbounded loops remain unsupported or incomplete. No DOS/BIOS
environment or C++/Pascal runtime is inferred. ELF objects and raw AMD64 scalar
code have independent positive and negative tests.

`inspect` can read formats recognized by CLE, including its executable/object
metadata. That does not qualify symbolic execution of all those architectures.
Focused disassembly currently supports x86 16/32/64; execution supports the two
profiles above. Relocations are shown, not automatically normalized or accepted.

## Verification

```sh
python -m pytest -q -ra
python tools/smoke.py
```

Tests include arithmetic encodings, carry and output-byte counterexamples,
wrong globals, changed branches, segment aliases, unknown calls, symbolic
control, bounds, missing memory, and separate C/C++ ELF objects when clang is
available. Synthetic examples need no proprietary inputs. Original game bytes and proprietary toolchains are not distributed. The
[capability summary](docs/CAPABILITIES.md) describes the bounded conclusions
from the historical bitfield investigation.

[Build instructions](docs/BUILDING.md) describe reproducible source and wheel
builds. [GitHub Actions](https://github.com/curiosalon/binquery/actions)
records actual host test results. Each invocation reads the caller-supplied inputs and writes its result to stdout.
