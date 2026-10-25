# Report a problem

Use [GitHub Issues](https://github.com/curiosalon/binquery/issues/new/choose)
for bugs, confusing behavior, or work that takes more steps than it should.
Describe what you were trying to find out and where you got stuck.

A useful report includes:

- `binquery --version`, OS, Python version, and installation method.
- The exact command and working directory, expected result, actual result, and exit code.
- JSON output and relevant stderr. For a wrapper, include its argument array
  and the nested binquery result.
- A small binary and contract that reproduce the problem, when possible.
- Any workaround you found.

If execution paused, include its reason and limits. If a result looks wrong,
show the input that contradicts it. A short synthetic example is usually
easier to investigate than a whole executable.

## Keep a local report

The optional [binquery skill](../skills/binquery/SKILL.md) includes a helper for
keeping reports locally. It records a command and evidence paths without
executing the command or uploading anything. This is useful when several
callers share one installation, or when a reproduction needs to stay local.

See the [report format and commands](../skills/binquery/references/reporting.md).
Reports can be listed and resolved when maintenance is requested. No service
or scheduled task is required.
