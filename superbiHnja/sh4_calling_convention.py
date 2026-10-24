"""SH-4 calling convention (Renesas SH-4 ABI)."""

from binaryninja import CallingConvention


class SH4CallingConvention(CallingConvention):
    name = 'sh4-default'
    int_arg_regs = ['r4', 'r5', 'r6', 'r7']
    float_arg_regs = ['fr4', 'fr5', 'fr6', 'fr7']
    int_return_reg = 'r0'
    high_int_return_reg = 'r1'
    float_return_reg = 'fr0'
    callee_saved_regs = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']
    implicitly_defined_regs = ['r15']


class SH4StackCallingConvention(CallingConvention):
    """All integer arguments on the stack (no argument registers).

    Variadic logger/assert helpers in SH firmware are called this way: the
    format string, file and line are pushed rather than passed in r4-r7.
    Apply it to such a function (and give it an explicit prototype) so its
    stack arguments, e.g. a __FILE__ string, resolve in the decompilation.
    """
    name = 'sh4-stack'
    int_arg_regs = []
    float_arg_regs = []
    int_return_reg = 'r0'
    high_int_return_reg = 'r1'
    float_return_reg = 'fr0'
    callee_saved_regs = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']
    implicitly_defined_regs = ['r15']
