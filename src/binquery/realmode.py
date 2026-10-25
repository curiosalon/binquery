"""Target adapter: 16 bit x86 instructions in a 32 bit physical address space.

No compiler frames, routine addresses, application names or service stubs belong
here. Near CALL/RET and stack instructions execute their actual SLEIGH semantics.
"""

import angr
import archinfo
from angr import claripy

from .model import Unsupported

LANGUAGE = "x86:LE:16:Real Mode"


def architecture():
    arch = archinfo.ArchPcode(LANGUAGE)
    # SLEIGH advertises instruction mode 16, but EIP and segment() use physical
    # 32 bit addresses. CLE and angr memory must not truncate those to 16 bits.
    # Individual SLEIGH register widths and the 16 bit language stay unchanged.
    arch.bits = 32
    arch.sizeof = {"short": 16, "int": 16, "long": 32, "long long": 64}
    return arch


class RealModeEngine(angr.engines.UberEnginePcode):
    def _execute_callother(self):
        op = self._current_op
        if (
            len(op.inputs) != 3
            or op.inputs[0].getUserDefinedOpName() != "segment"
            or op.output is None
            or op.output.size != 4
        ):
            raise Unsupported("Unmodeled p-code user operation")
        segment = self._get_value(op.inputs[1])
        offset = self._get_value(op.inputs[2])
        if segment.size() != 16 or offset.size() != 16:
            raise Unsupported("Only real mode segment:16-bit-offset translation")
        value = (claripy.ZeroExt(16, segment) << 4) + claripy.ZeroExt(16, offset)
        if not self.state.globals["a20"]:
            raise Unsupported("A20 disabled is not qualified")
        self._set_value(op.output, value)

    def _get_value(self, varnode):
        # Upstream supplies zero for an uninitialized unique. For proof queries
        # this must be an explicit unsupported operation, never an assumption.
        if varnode.space.name == "unique":
            if any(
                varnode.offset + i not in self._pcode_tmps for i in range(varnode.size)
            ):
                raise Unsupported("Uninitialized p-code temporary")
            parts = [
                self._pcode_tmps[varnode.offset + i]
                for i in reversed(range(varnode.size))
            ]
            return claripy.Concat(*parts) if len(parts) > 1 else parts[0]
        return super()._get_value(varnode)

    def _set_value(self, varnode, value):
        # The SLEIGH real-mode language synthesizes CS from the instruction's
        # high address bits before near control transfers. That loses valid
        # non-64KiB-aligned segments. The explicit machine contract owns CS;
        # qualify() rejects actual CS writes and every far transfer.
        if (
            varnode.space.name == "register"
            and varnode.offset == self.state.arch.registers["cs"][0]
        ):
            return
        # SLEIGH unique space is byte addressable; an operation may read a
        # subrange of an earlier wider temporary. Upstream assumes equal sizes.
        if varnode.space.name == "unique":
            value = self._adjust_value_size(varnode.size * 8, value)
            for i in range(varnode.size):
                self._pcode_tmps[varnode.offset + i] = value[i * 8 + 7 : i * 8]
            return
        return super()._set_value(varnode, value)
