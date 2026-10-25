# Report and repair

Save the command and its actual result before reducing the case. Distinguish
these common causes:

- Installation or wrapper failure: binquery never receives the request.
- Contract error: the supplied machine state is invalid or omits a needed fact.
- Unsupported behavior or a bound: the tool identifies work it did not finish.
- Tool bug: a crash, wrong answer, lost checkpoint, misleading diagnostic, or
  result inconsistent with the supplied contract.
- Usability friction: a task succeeds but needs repeated avoidable work.

Do not classify an unexplained failure as user error. Preserve enough evidence
to reproduce it, and state the uncertainty in `actual`.

## Save a report

Create a JSON request like this using the observed version and command:

```json
{
  "title": "Resuming with a higher address limit still uses the old limit",
  "kind": "bug",
  "impact": "blocker",
  "binquery_version": "0.8.2",
  "cwd": "/path/to/reproduction",
  "argv": ["binquery", "analyze", "--resume", "run.bq", "--addresses", "4"],
  "expected": "The retained symbolic read can use all four addresses.",
  "actual": "The report advertises four addresses but the read still fails at one.",
  "status": "ERROR",
  "exit_code": 4,
  "evidence": ["contract.json", "stderr.log", "result.json"],
  "workaround": "Start a new analysis with the larger address limit."
}
```

Then run the helper from this skill's directory:

```sh
python scripts/report_issue.py submit request.json --directory /path/to/writable/reports
python scripts/report_issue.py list --directory /path/to/writable/reports
```

Choose a directory the caller can write. Without `--directory`, the helper uses
`BINQUERY_REPORT_DIR`, then `$XDG_STATE_HOME/binquery/reports`, then
`~/.local/state/binquery/reports`. The shared directory is useful when callers
and the maintainer run on the same machine. A sandboxed caller can instead use
its assigned workspace and include the saved report path in its handoff.

Set `cwd` to the absolute working directory of the failing command, not the
skill directory. Relative arguments and evidence paths are interpreted against
that recorded directory. Use absolute evidence paths for files elsewhere.

The helper records the supplied fields and creates a unique local file. It
does not execute `argv` or collect referenced files. Add OS, Python and installed
dependency versions under `environment` when relevant, and a `transport`
description for wrapper failures. These are facts about the failing tool's
environment, which may differ from the helper's Python environment.

Small synthetic binaries are preferable for reproduction. Keep full paths and
local evidence in the private report; prepare a separate sanitized reproduction
when public submission is requested. Review text and attachments before any
external submission. Recording a report does not authorize sending messages or
opening an issue.

## Maintainer intake, on request

Read the specified report or list the local queue. Deduplicate by command,
symptom, version and existing resolution. Reproduce in an isolated directory
with the retained inputs or a minimal synthetic equivalent.

Put instruction semantics, generic queries, checkpoint behavior, packaging and
CLI diagnostics in binquery. Put project address translation, source discovery,
caller facts, sandbox policy and acceptance decisions in the consumer adapter
or configuration. Prefer an existing command over a duplicate implementation.

For a correctness fix, keep a regression that failed before the change and
checks the repaired behavior. Review the exact change, run the relevant checks,
and record the version or commit and the test result. For a usability report,
exercise the original calling sequence after the change.

```sh
python scripts/report_issue.py resolve REPORT_ID --directory /path/to/writable/reports --summary "Updated retained solver and address policies on resume; regression passes." --version 0.8.3 --evidence /path/to/test-result.txt
```

A report can also be resolved by a documented adapter correction or explanation
of supported behavior. Describe that outcome accurately. Communicate it through
the current task's handoff, or an explicitly authorized reply to the caller.
Work begins on a maintenance request; do not add polling or a schedule.
