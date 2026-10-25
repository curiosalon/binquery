---
name: binquery
description: Use binquery to compare compiled routines, explore bounded execution, trace memory writes, or enumerate indirect targets. Record and investigate binquery bugs or usability friction from actual calls. Use for a concrete machine-code question or binquery maintenance request.
---

# binquery

Choose the smallest question that resolves the caller's uncertainty. A routine
that already has adequate evidence does not need another symbolic analysis.

## Choose a command

| Question | Command and contract |
| --- | --- |
| Do two implementations preserve selected outputs? | `compare`, machine schema 1; add a comparison contract for named memory or relocated storage. |
| Is a register preserved, a return constant, or a read unreachable? | `query`, machine schema 1 claims. |
| Which destinations can this indirect transfer reach? | `targets`, machine schema 1 and an explicit input domain. |
| What executes, what changes, and which write supplies a read? | `analyze`, analysis schema 2; then `query --analysis`, `report`, or `graph`. |

Start with the installed `binquery --version` and the relevant command's
`--help`. Reuse a supplied contract or saved analysis. `schema --kind analysis
--schema-only` and `example --kind analysis --arch real16 --json` describe the
current execution interface. Examples are synthetic starting points, not
evidence for another binary's initial state.

Read [calling.md](references/calling.md) when preparing a contract, resuming
execution, or using a wrapper. The public
[tutorials](https://github.com/curiosalon/binquery#learn-by-doing) include complete
examples for bit extraction, compiled C/C++, and saved execution.

## Interpret the result

Use the question's result and scope, not just process success. Record the input
identities, declared domain, selected outputs, and replay result with the answer.
An observed target is not automatically a valid function entry. A representative
replay checks a concrete case; symbolic coverage comes from the retained domain
and completion fields.

If execution stops at a cap, inspect the retained reason and raise only the
relevant limit. If the contract lacks a caller fact, obtain that fact or leave
the question unresolved. Do not substitute zeroes for unknown input or invent
an external service's behavior to obtain a successful result.

## Report a problem

Report reproducible bugs, repeated manual work, confusing results, and missing
capabilities that obstruct the current task. Keep working when a justified
workaround exists, and record it. Do not retry an unchanged failure repeatedly.

Use [reporting.md](references/reporting.md) to save a small local report with
`scripts/report_issue.py`. Include its path in the caller's existing handoff.
The helper does not contact anyone, create GitHub issues, or schedule work.
Read the same reference when asked to maintain binquery: inspect open reports,
reproduce the problem, fix it at the appropriate layer, and retain the result.
