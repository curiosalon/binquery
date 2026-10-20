# Command and contract reference

For a first run, use the [add-one example](../README.md#try-it-two-ways-to-add-one)
or the [packed-bit tutorial](CAPABILITIES.md).

## Commands

| Command | Purpose |
| --- | --- |
| `inspect` | Show symbols, selected instructions, bytes, and relocation metadata. |
| `query` | Check a property of one binary. |
| `compare` | Compare selected outputs of two binaries. |
| `replay` | Run a saved counterexample through Unicorn. |
| `schema` | Print the machine or comparison JSON Schema. |
| `example` | Print a sample contract or a bundle of example files. |

Use `binquery COMMAND --help` for options. Human-readable output is the default;
`--json` writes a structured result to stdout. Diagnostics go to stderr.
`python -m binquery` is equivalent to `binquery`.

`inspect` uses CLE to read executable and object formats. Select a function
with `--symbol NAME`, or a loaded address range with `--address` and `--size`.
For raw code, use `--format blob --arch ARCH --base ADDRESS`; `--offset` and
`--size` select bytes within the file. Focused disassembly supports x86 16, 32,
and 64-bit code.

## Machine contracts

A contract is a JSON description of the machine at the start of a routine.
It supplies the context that a caller, loader, or operating system would
normally provide.

This is a complete contract for the repository's `examples/inc.bin`:

```json
{
  "schema": 1,
  "architecture": "x86:LE:16:Real Mode",
  "entry": "0x11000",
  "code": [{"address": "0x11000", "size": 1}],
  "stops": [{"address": "0x11001", "kind": "boundary"}],
  "registers": {
    "cs": "0x1000", "ds": "0x4000", "ss": "0x7000",
    "es": "0xa000", "sp": "0x8000"
  },
  "flags": "0x202"
}
```

Numbers may be JSON integers or strings such as `"0x11000"`. Register names
are lowercase. Unlisted general registers are symbolic; the two sides of a
comparison begin with the same values.

| Field | Meaning |
| --- | --- |
| `schema` | Contract version, currently `1`. |
| `format` | `blob` for raw bytes, the default; `auto` for CLE loading. |
| `architecture` | `AMD64` or `x86:LE:16:Real Mode`. Required for raw bytes. |
| `entry` | Starting address: physical for real mode, loaded virtual address for AMD64. |
| `code` | Code ranges with `address` and `size`. Raw ranges may also specify `offset`, auxiliary `file`, and whole-file `sha256`. |
| `stops` | Addresses outside the code with kind `return`, `failure`, or `boundary`. |
| `registers` | Concrete values or symbolic unsigned ranges. |
| `flags` | Initial flags; `0x202` is used in the examples. |
| `memory` | Initial RAM bytes or symbolic values. |
| `claims` | Properties checked by `query`. |
| `limits` | Bounds on time, paths, instructions, and address exploration. |
| `a20` | `true`, the supported real mode address setting. |
| `shift_count` | `portable`, the default, or `masked5` for 286-and-later count masking. |

For real mode, supply concrete CS, DS, SS, ES, and SP. Physical addresses use
`segment * 16 + offset`. Code and stop addresses must fit the same CS window.
For AMD64, supply the stack and arguments according to the function's calling
convention; the [compiled-function example](COMPILED.md) shows one setup.

Code ranges must be explicit. `inspect --symbol` can obtain a size from a
symbol table; otherwise determine the extent in your disassembler. Include
shared tails and called helper code as additional ranges. Raw auxiliary file
paths resolve relative to the contract. In `auto` mode, ranges use loaded
addresses rather than file offsets.

### Inputs and memory

To restrict AX to values from 0 through 15:

```json
"ax": {"symbolic": true, "min": 0, "max": 15}
```

Memory rows contain either literal bytes or a symbolic value:

```json
[
  {"address": "0x78000", "hex": "00f1"},
  {"address": "0x78002", "symbolic": true, "size": 2, "min": 0, "max": 3}
]
```

The first row contains two bytes, `00 f1`. The second contains a little-endian
unsigned 16-bit value from 0 through 3. Omitting `min` and `max` allows every
value of that size. Reads must refer to initialized RAM, selected code, or bytes
already written during execution. An uninitialized read is reported so you
can add the missing input.

### Query claims

```json
[
  {"kind": "preserved", "register": "bx"},
  {"kind": "return_equals", "register": "ax", "value": 0},
  {"kind": "no_read", "instruction": "0x11000"}
]
```

`preserved` checks a register at every stop. `return_equals` checks stops marked
`return`. `no_read` checks whether a particular memory-reading instruction can
be reached and perform a read. It must name a decoded memory-reading instruction;
an unreachable valid site is reported as not reached.

Generate a starter contract or schema with:

```sh
binquery example --arch AMD64 --contract-only > machine.json
binquery schema --schema-only > machine.schema.json
binquery schema --kind comparison --schema-only > comparison.schema.json
```

## Selecting comparison outputs

Repeat `--observe` to select registers or arithmetic flags:

```sh
binquery compare old.bin new.bin --contract old.json --right-contract new.json --observe ax --observe bx --observe cf
```

Here the files are your own binaries and contracts. Stop kinds are compared
automatically. `--observe-memory ADDRESS:SIZE` selects final RAM at the same
address in both images. `--effects` also compares the address, width, value,
and order of memory reads and writes.

For named output regions, put them in a comparison file:

```json
{
  "schema": 1,
  "memory": [
    {"name": "result", "left": "0x40100", "right": "0x40100", "size": 4}
  ]
}
```

Pass it with `--comparison FILE`. Include neighboring bytes if preserving them
is part of the question. The JSON result reports writes outside the selected
final memory regions to help you spot omissions.

### Different storage addresses

The real mode layout comparison relates named RAM regions and near register
pointers between builds. The [layout example](CAPABILITIES.md#when-data-moves-between-builds)
creates a complete pair of contracts.

In its comparison file, `relation.regions` maps every initial RAM row to its
counterpart. Corresponding rows have equal sizes and the same value ranges.
Top-level `memory` selects final output bytes. Top-level `pointers` selects
output registers interpreted as pointers; `relation.pointers` describes input
pointers. Each pointer names a register, DS or ES, and a region. Comparison uses
its byte offset within that region.

Regions are disjoint, with at most 64 regions and 4096 bytes per relation.
Final-memory observations have the same separate bounds. The segments and
initial SP are equal across images. The optional `relation.stack` fixes the
stack window; without it, the whole SS segment is reserved for the stack.
Stack data stays at its original addresses.

This mapping supports near pointers in registers into a single named RAM
region. Embedded pointers, null or one-past pointers, far pointers, and moving
stack or code addresses need a different adapter. Raw `--observe ax` and
`--effects` still compare numeric values and physical addresses.

## Results and exit codes

| Result | Meaning | Exit |
| --- | --- | --- |
| `ESTABLISHED_WITHIN_MODEL` | The query property holds for the declared inputs. | 0 |
| `EQUIVALENT_WITHIN_MODEL` | The selected outputs agree for the declared inputs. | 0 |
| `REFUTED` / `DIFFERENT` | A concrete counterexample was checked by Unicorn. | 1 |
| `INCONCLUSIVE` / `UNSUPPORTED` | A limit or unsupported operation prevented an answer. | 2 |
| `INVALID` | The inputs or contract need correction. | 3 |
| `ERROR` | The tool encountered an internal error. | 4 |

Successful inspection, schema output, example output, and replay also exit 0.
For multiple query claims, an incomplete result takes precedence over a refuted
claim in the exit code; JSON retains each claim's result.

“Within model” refers to the input ranges, machine setup, and outputs selected
by the contract. For example, comparing AX establishes nothing about CF until
you select CF too. `byte_match` is a separate comparison of the selected code
bytes.

Comparison JSON includes `comparisons` for each aspect, a `witness` when a
difference is found, and `replay` results. A replay checks the saved input,
instruction path, stop, registers, and memory events. Saved results include
binary and contract hashes, so replay detects changed inputs.

## Supported code

The execution engines are angr's VEX backend for AMD64 and p-code backend for
16-bit x86 real mode. Current support centers on scalar integer routines:

- MOV forms, LEA, ADD/SUB/CMP/INC/DEC, AND/OR/XOR, PUSH/POP, near CALL/RET,
  JMP, ordinary conditional branches, and NOP.
- Real mode also supports CLD/STD, TEST, NOT, unsigned MUL, SHL/SHR, and
  byte/word RAM arithmetic. DS/ES updates need a single concrete result.
- Near indirect control must resolve to one supplied code address or stop.
  Symbolic memory addresses are explored as finite sets.
- Real mode tracks CF/PF/ZF/SF/OF validity. A branch or requested output that
  depends on an undefined flag reports `UNSUPPORTED`. AF is not observable.
  Default shift counts are 0 through 31; `masked5` selects five-bit masking.

Floating point, vector code, far calls/returns, interrupts, devices, and
self-modifying code are unsupported. External calls need supplied code;
operating systems, C++ exception handling, and language runtimes are not
automatically modeled. Inspection can recognize more formats and architectures
than execution supports.

The real mode adapter handles segmented addresses and p-code temporary storage.
It also corrects SHR overflow-flag behavior at counts zero and one and combines
repeated p-code operand loads into one instruction's RAM access after checking
their values and widths.

## Limits and troubleshooting

| `limits` field | Default | Maximum |
| --- | --- | --- |
| `steps` per path | 128 | 4096 |
| `states` pending plus completed | 256 | 4096 |
| `seconds` per image | 30 | 300 |
| `solver_ms` per solver check | 5000 | 60000 |
| `addresses` per symbolic memory access | 32 | 256 |

If a result is incomplete, read `issues` in the JSON output. Add missing
memory or helper code, narrow a pointer's input range, or increase the relevant
limit. An unexplored path prevents an equivalence result.

Some AMD64 code that accesses RAM on its own code page encounters a Unicorn
memory-hook limitation during replay. Such a result remains inconclusive;
use separate code and data pages in synthetic examples.
