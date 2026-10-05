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
