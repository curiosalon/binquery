# Calling binquery

## Contracts and adapters

Reuse the caller's verified mappings, code extents, entries, and input ranges.
A disassembler adapter can generate the mechanical JSON fields; the caller
still owns facts about arguments, stack frames, external responses, and memory
mutability. Keep that translation in the consumer, rather than teaching
binquery about a particular project database.

For 16-bit code, preserve segment:offset identity as well as the physical
address. Record the architecture and entry's `program`, `space`, and
`load_context`. Analysis mappings carry `permissions`; writable code is allowed
and is decoded from the current machine state. Do not mark a mutable table
immutable simply because its initial bytes came from a file.

Unlisted general registers are symbolic. Reads still need declared memory or
memory written by the program. Real mode requires concrete CS, DS, ES, SS and
SP. Missing segment values or unknown external behavior need caller evidence,
not a guessed contract. Use the published schema and runtime validation;
neither infers those facts.

## Saved execution

These commands assume the caller has supplied `routine.bin` and `analysis.json`:

```sh
binquery analyze routine.bin --contract analysis.json --save run.bq --steps 128 --json
binquery report run.bq --json
binquery analyze --resume run.bq --steps 512 --json
binquery query --analysis run.bq --kind access --access write --range 0x40200:2 --expect always --json
binquery query --analysis run.bq --kind last-write --site 0x1100f --json
binquery graph run.bq --view memory --format dot
```

`--steps` is a cumulative depth per path. Resuming with 512 allows depth 512;
it does not grant 512 additional instructions. Caps on addresses, variants,
events, states, time, and checkpoint size are separate. Read the pause reason
before choosing an override. A new analysis requires an unused save path.

`report --check-inputs` verifies the saved input files and implementation
identity. Resume requires those identities to match. A `.bq` file contains
Python machine states: resume only a trusted locally generated checkpoint.
`report`, `query --analysis`, and `graph` read its portable JSON without
restoring those states.

Save a JSON report, question JSON and answer JSON for durable findings. Retain
the contracts and input hashes with them. A local checkpoint is useful for
continuation; it is not a relocatable bundle of input files. Currently the CLI
reads saved trace queries from `.bq`, not from an exported standalone JSON file.

## Shell and wrapper calls

In a shell, use `--json > result.json`. In a tool wrapper that takes an argument
array, pass tokens, without shell redirection:

```json
{"arguments":["analyze","routine.bin","--contract","analysis.json","--save","run.bq","--steps","128"]}
```

Use the wrapper's own output capture. Its successful process or transport
status can contain binquery `INCONCLUSIVE` and exit code 2. Inspect the nested
`output`, `status`, and `exit_code` when present. Save paths must remain inside
the caller's writable workspace. Do not broaden permissions to resume a run.

Comparisons exit 0 for agreement, 1 for a difference, 2 for incomplete work,
3 for invalid input, and 4 for a tool error. Saved trace queries use
`ESTABLISHED`, `REFUTED`, and `INCONCLUSIVE`. For `targets`, inspect `complete`,
`domain_exhausted`, `issues`, the initial assumptions, each target's witness and replay; use
`--require-complete` when the shell needs incompleteness to fail the command.

## Choosing a trace question

`access` selects reads or writes. `last-write` identifies the suppliers of each
byte at a read; partial writes can produce several suppliers. `modified-code`
finds executed instructions whose bytes were changed. `flow` asks whether an
execution reaches a destination. `memory-effect` checks a byte fill or snapshot
copy at an explicit `--to` stop. Copy requires disjoint ranges, a written
destination, and a source read without intervening writes. For access and
last-write questions, use `--path` and `--event` to distinguish repeated visits.
Use `--questions FILE` for a JSON array of related questions.

`possible` asks for a satisfying case; `always` asks whether the property holds
throughout the selected domain; `never` asks whether it is absent. A partial
trace can establish a witnessed possibility but cannot justify a universal
absence claim. Read each answer's scope and status.
