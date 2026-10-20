# Compare compiled C and C++ functions

You can use binquery to check a replacement function, investigate a compiler
change, or compare two implementations of an algorithm. This example starts
with a small function:

```c
unsigned long add_one(unsigned long value)
{
    return value + 1;
}
```

The repository supplies a C version in `examples/scalar.c`, a C++ version in
`examples/scalar.cpp`, and an intentionally different version in
`examples/different.c`. The C++ version uses `extern "C"` so its symbol is also
named `add_one`.

## Compile and inspect

Install binquery using the [README](../README.md#install). For this example you
also need Clang on your PATH. Run these commands from the repository directory:

```sh
clang --target=x86_64-unknown-linux-gnu -O2 -ffreestanding -c examples/scalar.c -o scalar.o
clang --target=x86_64-unknown-linux-gnu -O2 -ffreestanding -c examples/scalar.cpp -o scalar-cpp.o
clang --target=x86_64-unknown-linux-gnu -O2 -ffreestanding -c examples/different.c -o different.o
binquery inspect scalar.o --symbol add_one
```

The explicit target makes Clang produce AMD64 ELF objects on each host.
There is no linking step, and these sources need no system headers.
`inspect` shows the instructions and their addresses. It gets the function
extent from the object's symbol table.

## Compare the functions

The supplied [comparison script](../examples/compare_functions.py) creates the
contracts and calls binquery:

```sh
python examples/compare_functions.py scalar.o scalar-cpp.o --output demo-compiled
```

The script creates a new results directory; use a fresh name for each run.
It prints `EQUIVALENT_WITHIN_MODEL`. Open `demo-compiled/result.json` for the
full result, or repeat the comparison directly:

```sh
binquery compare scalar.o scalar-cpp.o --contract demo-compiled/left.json --right-contract demo-compiled/right.json --observe rax
```

Now compare the version that adds two:

```sh
python examples/compare_functions.py scalar.o different.o --output demo-different
```

This prints `DIFFERENT` and exits with code 1. Its result file includes an
input in RDI, the two output values in RAX, and both emulator replays.

## What the script supplies

A function normally starts with arguments and a return address prepared by its
caller. The contract supplies that small amount of context:

- The symbol's address and size select the code to execute.
- The stack pointer, RSP, points to an eight-byte return address.
- The return address is a stop marked `return`.
- RDI, the argument register in the AMD64 System V calling convention, is left
  symbolic. This covers every 64-bit unsigned argument.
- `--observe rax` selects the return value.

Both functions receive the same initial input. When they reach the return
stop, binquery asks whether their RAX values can differ.

## Adapt it to another function

For another simple function with this calling convention, pass its symbol:

```sh
python examples/compare_functions.py old.o new.o --symbol calculate --output calculation
```

Here `old.o` and `new.o` are your own object files. Inspect the instructions and
edit the generated contracts as needed. Pointer arguments need memory
declarations; stack arguments need bytes at their stack addresses. Include any
helper code the routine calls, and choose the registers or memory that contain
its outputs.

The script is deliberately short so you can change these assumptions. Its
starting contract fits integer functions without code relocations or external
calls. Other calling conventions and richer runtimes need their own setup.
See the [contract reference](REFERENCE.md#machine-contracts) for the fields.

## Use the command from a script

Handle a discovered difference as a useful result. This Python example works
on Linux, macOS, and Windows with the same installed environment:

```python
import json
import subprocess
import sys

done = subprocess.run(
    [
        sys.executable, "-m", "binquery", "compare",
        "scalar.o", "scalar-cpp.o",
        "--contract", "demo-compiled/left.json",
        "--right-contract", "demo-compiled/right.json",
        "--observe", "rax", "--json",
    ],
    capture_output=True,
    text=True,
    encoding="utf-8",
)
result = json.loads(done.stdout)
if done.returncode == 0:
    print("The return values agree.")
elif done.returncode == 1:
    print("Different return values:", result["replay"])
else:
    print("Analysis did not finish:", result)
    raise SystemExit(done.returncode)
```
