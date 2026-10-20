# What binquery can establish

binquery is a command-line tool for asking bounded questions about machine
code. It uses angr for symbolic execution and constraint solving, then
checks counterexamples independently with the Unicorn CPU emulator.
Inputs are ordinary binaries and explicit JSON contracts. Results are
structured JSON, meaningful exit codes, and replayable witnesses.

| Capability | What it answers |
| --- | --- |
| Inspect | What symbols, bytes, instructions and relocation metadata are in a selected range? |
| Query | Is a register preserved, does a return register equal a value, or can a specified instruction read memory? |
| Compare | Do two declared input domains produce the same selected registers, exit kind, final RAM or pointer outputs? |
| Ordered effects | Do reads and writes agree in address, width, value and order? |
| Explicit layout relation | Do corresponding real16 RAM regions and declared near register pointers agree despite different linked addresses? |
| Replay | Does an independently emulated concrete execution reproduce a counterexample? |

Execution currently qualifies selected scalar AMD64 and 16-bit x86 real
mode instructions. The real mode adapter handles physical segment
translation, near frames and SLEIGH temporary storage. Packed-field support
includes bitwise operations, TEST, NOT, unsigned MUL, shifts, direction-flag
control and qualified memory arithmetic. Undefined flag dependencies and
CPU assumptions remain explicit. Inspection supports more input formats
than execution; recognizing a binary does not establish its ABI or runtime.

The source language is not a parameter. A compiled C, C++, Pascal or assembly
routine can be studied if its instructions and supplied environment fit the
model. Small C and C++ ELF fixtures are tested. Pascal runtimes, C++ exceptions,
virtual dispatch and arbitrary libraries are not automatically modeled.

## Role in the packed-bit investigation

binquery separated three questions that often get confused: identical
instruction bytes, identical selected outputs, and identical memory effects.
One getter comparison returned the same AX value while exposing a real
byte-versus-word read difference. Both counterexample executions replayed.
That distinction matters when neighboring bytes, aliases or volatile
interactions could make a wider read observable.

For one Wizardry VI scalar extractor, a 30-byte compiled C candidate agreed
with the 35-byte original on AX and selected preserved state across every
16-bit value, shifts 0 through 15, and widths 1 through 16:
65,536 × 16 × 16 = 16,777,216 input combinations. This was a symbolic result
under explicit fixed machine/stack assumptions, not 16 million native tests.
Working registers differed with replayed evidence. Other flags, ordered
effects and undeclared initial states were outside that equality claim.

The wider investigation subsequently produced one shared assembly library
recipe with a C interface matching all five packed-bit functions in both
games. Exact assembly matching and executed caller fixtures were separate
compiler/reconstruction checks. binquery contributed behavioral evidence
and counterexamples; it did not synthesize the library or prove its historical
authorship. The original source and build recipe remain unknown.

These game-specific results are historical local evidence. Original game
bytes, proprietary compiler files and private execution receipts are not
distributed. The public synthetic examples reproduce the tool's functional,
access-order and relocated-storage distinctions without those inputs.

## Limits readers should retain

“Equivalent within model” means all completed paths in the supplied input
domain agree on the selected observations. It does not cover omitted state
or a larger input domain. A limit, unknown call, unresolved target or
unsupported operation prevents a proof claim.

Layout correspondence is deliberately narrow: fixed equal segments and a
fixed stack window, explicit disjoint RAM regions, and bounded near register
pointers through DS/ES. There is no inferred object graph, embedded-pointer
translation, far control, device/interrupt model, arbitrary relocation,
automatic function discovery, source reconstruction or universal equivalence.
Native replay checks concrete witnesses; it is not a proof that every
symbolic backend instruction is correct. A known AMD64 same-code-page RAM
hook issue conservatively leaves some replays inconclusive.

## Short description for an article

> binquery turns a machine-code hypothesis into a bounded, repeatable test.
> Given two binaries and an explicit description of their inputs and outputs,
> it can establish equality within that model or produce a concrete difference
> checked by a second execution engine. In our packed-bit investigation, this
> let us distinguish a correct functional reconstruction from an exact
> instruction match and expose memory-access differences hidden by equal
> return values.

Copyright (c) 2026 Curio Salon

Written under the direction of Curio Salon using the GPT-6 Astra model.
Distributed under the OpenBSD ISC license wording in [LICENSE](../LICENSE).
