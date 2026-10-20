# Working with packed bits

Suppose you are reading assembly from an old program. One routine appears to
extract a small field from a larger value. You have written a replacement, but
the instructions look different. How can you check your interpretation?

This tutorial uses a three-bit field starting at bit 4:

```text
bit:    15 14 13 12 11 10 9 8 7 [6 5 4] 3 2 1 0
                                  field
```

In C, extracting that field from an unsigned 16-bit value looks like:

```c
unsigned extract(unsigned value)
{
    return (value >> 4) & 7;
}
```

Shifting right moves the field into bits 0 through 2. The mask `7`, binary
`111`, keeps those three bits. The result is a number from 0 to 7.

## Set up the example

First [install binquery](../README.md#install), then run this from the repository
directory:

```sh
python examples/make_demo.py bitfield demo
```

The script creates a new `demo` directory containing three binaries and their
JSON contracts. It also writes an assembly listing beside each binary. You
can read [the script](../examples/make_demo.py) to see exactly how it builds them.
Choose a different directory name if `demo` already exists.

Inspect the first binary:

```sh
binquery inspect demo/word.bin --format blob --arch "x86:LE:16:Real Mode" --base 0x11000
```

Its instructions are:

```asm
mov ax, word ptr [0x100]
shr ax, 4
and ax, 7
```

The replacement reads only the low byte, clearing AX first:

```asm
xor ax, ax
mov al, byte ptr [0x100]
shr ax, 4
and ax, 7
```

Both versions read from the same two-byte input in RAM. The contracts set DS
to `0x4000`, so DS:`0x100` refers to physical address `0x40100`. The memory
declaration leaves that word symbolic:

```json
{"address": "0x40100", "symbolic": true, "size": 2}
```

This asks binquery to consider every possible 16-bit word.

## Compare the extracted value

```sh
binquery compare demo/word.bin demo/byte.bin --contract demo/word.json --right-contract demo/byte.json --observe ax
```

The result is `EQUIVALENT_WITHIN_MODEL`. The two versions return the same AX
value for all 65,536 input words. Reading the low byte is enough because all
three selected bits are in that byte.

The bytes of the routines differ. Their return values agree. Those are useful
facts to keep separate when replacing code or investigating compiler output.

You can also ask about one routine on its own:

```sh
binquery query demo/word.bin --contract demo/word.json
```

The example contract includes a `preserved` claim for BX. The result,
`ESTABLISHED_WITHIN_MODEL`, confirms that BX keeps its initial value.

## Catch a wrong mask

The third version uses `and ax, 3`, keeping two bits instead of three:

```sh
binquery compare demo/word.bin demo/wrong.bin --contract demo/word.json --right-contract demo/wrong.json --observe ax --json > demo/wrong-result.json
```

This returns `DIFFERENT` and exits with code 1. For example, input `0x0040`
should produce 4; the wrong mask produces 0. The solver can choose any input
that exposes the error, so its saved example may use a different word.

The saved JSON contains the input under `witness` and the checked executions
under `replay`. This short Python script prints the useful parts:

```python
import json
from pathlib import Path

result = json.loads(Path("demo/wrong-result.json").read_bytes())
raw = result["witness"]["left"]["memory"][0]["hex"]
print("Input word:", hex(int.from_bytes(bytes.fromhex(raw), "little")))
for side in ("left", "right"):
    execution = result["replay"][side]
    print(side, "AX:", execution["registers"]["ax"])
```

A counterexample gives you a concrete case to inspect in a debugger or add
to your own tests. To replay it with binquery:

```sh
binquery replay demo/word.bin --contract demo/word.json --witness demo/wrong-result.json --side left --aspect registers
binquery replay demo/wrong.bin --contract demo/wrong.json --witness demo/wrong-result.json --side right --aspect registers
```

Both report `REPLAYED`.

## Compare the reads, too

Return values are only one part of a routine's behavior. Ask about memory
accesses by adding `--effects`:

```sh
binquery compare demo/word.bin demo/byte.bin --contract demo/word.json --right-contract demo/byte.json --observe ax --effects --json > demo/reads.json
```

The registers still agree, but `ordered_memory_effects` is `DIFFERENT`.
One version reads two bytes; the other reads one. This script shows the
actual accesses from the replay:

```python
import json
from pathlib import Path

result = json.loads(Path("demo/reads.json").read_bytes())
for side in ("left", "right"):
    print(side)
    for event in result["replay"][side]["events"]:
        print(event["kind"], hex(event["address"]), event["size"], "byte(s)")
```

This distinction matters when you are trying to reproduce an original routine's
access pattern, or when the neighboring byte should not be touched. It also
helps explain why two plausible source expressions can produce meaningfully
different machine code.

## Compare what is left in memory

Sometimes the output is a buffer rather than a register. Create another example:

```sh
python examples/make_demo.py final-memory demo-memory
```

The left version stores the word `0x0201`. The right version stores byte `1`
and then byte `2`. On little-endian x86, both leave the bytes `01 02` in RAM.

```sh
binquery compare demo-memory/left.bin demo-memory/right.bin --contract demo-memory/left.json --right-contract demo-memory/right.json --comparison demo-memory/comparison.json
```

This reports agreement on `final_memory`. Add `--effects`:

```sh
binquery compare demo-memory/left.bin demo-memory/right.bin --contract demo-memory/left.json --right-contract demo-memory/right.json --comparison demo-memory/comparison.json --effects
```

Now the overall result is `DIFFERENT`: one word write and two byte writes have
different access patterns, even though the finished buffer is identical.

## When data moves between builds

Rebuilding a program can move its globals. A returned pointer may change
numerically while still pointing to the same logical result.

```sh
python examples/make_demo.py layout demo-layout
binquery compare demo-layout/left.bin demo-layout/right.bin --contract demo-layout/left.json --right-contract demo-layout/right.json --comparison demo-layout/comparison.json
```

Here the left program stores its result at `0x40100`, while the right stores it
at `0x40200`. The comparison file names the corresponding regions and describes
AX as a near pointer into the result region. Both the stored bytes and the
pointer's position within the result agree.

Open `demo-layout/comparison.json` to see the mapping. Add `--observe ax` to
compare the raw pointer numbers as well; that reports `DIFFERENT`.

## Use the same approach on your own code

Start with the question you are trying to answer. For a field extractor, that
might be “does it return the same number?” For a setter, it might be “does it
change the field while preserving the neighboring bits?”

Identify the routine's entry, arguments, memory, and return convention with
your disassembler or debugger. Put those facts in a
[contract](REFERENCE.md#machine-contracts). Select the return register and,
for a setter, the whole affected word or buffer. Including neighboring bytes
lets the comparison catch accidental writes outside the intended field.

binquery uses angr to follow the code with symbolic values. At a branch, it
can explore both feasible paths. It asks a constraint solver whether any input
can make the selected outputs differ. A successful equivalence result covers
the input ranges in the contract; a counterexample shows where your current
understanding breaks down.

The [compiled-function example](COMPILED.md) takes the next step: building C and
C++ object files and preparing their contracts with a small Python script.
