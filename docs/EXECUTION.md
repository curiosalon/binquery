# Follow a value through a program

Suppose a routine stores a value in memory and another instruction reads it.
You want to know which store supplied the read, and whether every input takes
that path. binquery can explore the inputs once, save the execution, and answer
several questions about it.

Run these examples from the repository root after installing binquery.

## Make a small program

```sh
python examples/saved_analysis.py trace-demo
```

The script creates `routine.bin` and `analysis.json`. The binary contains:

```asm
cmp ax, 5
jae clear
add ax, 3
jmp store
clear:
xor ax, ax
store:
mov [0200h], ax
mov bx, [0200h]
```

In plain terms, inputs 0 through 4 produce 3 through 7; all other inputs
produce zero. The last two instructions store that result and read it into BX.
AX starts symbolic, covering all 65,536 values of a 16-bit register.

The contract loads code at physical address `0x11000`, with CS=`0x1000`.
DS=`0x4000`, so `[0200h]` refers to physical address `0x40200`. The stop is
`0x11013`, immediately after the final instruction. These addresses come from
our example's contract; for another program, use its actual load arrangement.

## Pause and resume

Start with a deliberately small instruction budget:

```sh
binquery analyze trace-demo/routine.bin --contract trace-demo/analysis.json --save trace-demo/run.bq --steps 2
```

This returns `INCONCLUSIVE` with pending paths and exits with code 2. The
analysis reached its depth limit, and `run.bq` retains the unfinished states.
Continue them with a larger limit:

```sh
binquery analyze --resume trace-demo/run.bq --steps 128
binquery report trace-demo/run.bq
```

The result is `COMPLETE`, with two terminal paths. The limit is cumulative:
128 means each path may reach depth 128, not 128 additional instructions.

## Ask about memory

Does every input write the result word?

```sh
binquery query --analysis trace-demo/run.bq --kind access --access write --range 0x40200:2 --expect always
```

The answer is `ESTABLISHED`. Now ask which write supplies the read at `0x1100f`:

```sh
binquery query --analysis trace-demo/run.bq --kind last-write --site 0x1100f
```

For each path, both bytes come from the store at `0x1100c`. If the routine had
overwritten just one byte, the answer would identify a different supplier for
that byte. This is useful when reconstructing packed fields, overlapping
storage, or structures updated in several places.

The question defaults to `--expect possible`. Use `always` for a property that
must hold throughout the selected input domain, or `never` to test its absence.

## Save results for a script

Add `--json` when another program needs to read the answer:

```sh
binquery report trace-demo/run.bq --json > trace-demo/report.json
binquery query --analysis trace-demo/run.bq --kind access --access write --range 0x40200:2 --expect always --json > trace-demo/writes.json
binquery graph trace-demo/run.bq --view memory --format dot > trace-demo/memory.dot
```

Graphviz can turn the DOT file into a picture with
`dot -Tsvg trace-demo/memory.dot -o trace-demo/memory.svg`. Graph views include
control flow, calls, and memory dependencies.

In Python, check the command's exit code and the structured answer:

```python
import json
import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "binquery", "query", "--analysis", "trace-demo/run.bq",
     "--kind", "access", "--access", "write", "--range", "0x40200:2",
     "--expect", "always", "--json"],
    capture_output=True, text=True, encoding="utf-8", check=False,
)
answer = json.loads(result.stdout)
if result.returncode == 0 and answer["status"] == "ESTABLISHED":
    print("Every input writes the result word.")
else:
    print(answer)
    raise SystemExit(result.returncode or 1)
```

Use `--questions FILE` to submit an array of questions together. That avoids
reloading the saved report for each question.

## Other questions

| Kind | What it answers |
| --- | --- |
| `access` | Does a read or write touch a byte range? |
| `last-write` | Which earlier write supplies each byte of a read? |
| `modified-code` | Were executed instruction bytes changed before execution? |
| `flow` | Can execution reach a selected destination? |
| `memory-effect` | At a boundary, does a range contain a repeated byte or a copy of the initial source bytes? |

For a fill or copy, select a destination with `--range`, the boundary with
`--to`, and `--effect fill --value BYTE` or `--effect copy --source ADDRESS`.
Copy compares disjoint ranges at a stop: the destination must have been written,
and the source must have been read without being overwritten. Use `--path` to
select a path. For access and last-write questions, `--event` selects a particular
visit when an instruction executes more than once.

## Describe your own execution

```sh
binquery schema --kind analysis --schema-only > analysis.schema.json
binquery example --kind analysis --arch real16 --json > example.json
```

Analysis contracts use schema 2. They describe code and memory mappings, named
entries, initial registers, and optional stops. Each entry has a `program`,
`space`, and `load_context` so identical addresses in different programs or
overlays remain distinguishable. Mapping `permissions` describe readable,
writable, and executable storage. Code can be writable: binquery decodes the
bytes present when the instruction executes.

The execution model includes near and far transfers, explicit interrupt
handlers, stack frames, and declared port responses in 16-bit real mode. It
does not supply an operating system or infer device behavior. Add the code and
responses needed by the question. An unsupported instruction or missing input
appears in the report's issues.

## Keep the evidence you need

A report includes input hashes, mappings, entry identities, limits, path
conditions in SMT-LIB, ordered events, concrete witnesses, and native replay
results. Save the contract, report, question, and answer together when retaining
a finding. `report --check-inputs` checks the original files and implementation
identity without executing the program again.

The `.bq` file also contains Python machine states for continuation. Resume only
checkpoints you created and trust. Resume requires the same input files and
implementation; portable report, query, and graph operations do not restore
those states. There is currently no command to bundle and relocate the inputs.
