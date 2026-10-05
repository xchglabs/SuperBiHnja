"""SH-4 instruction decoder for Binary Ninja.

Decodes all 16-bit SH-4 (SH7750 family) instructions,
including FPU instructions.  Produces SH4Instruction, InstructionTextToken
lists, and InstructionInfo suitable for the Binary Ninja Architecture class.
"""

import struct
from typing import Optional, List

from binaryninja.function import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.architecture import InstructionInfo

from .sh4_types import (
    SH4Instruction, Operand, OperandType, BranchKind,
    REGS_GENERAL, REGS_BANKED,
    REGS_FR, REGS_DR, REGS_FV,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _se8(v: int) -> int:
    return v - 0x100 if v & 0x80 else v


def _se12(v: int) -> int:
    return v - 0x1000 if v & 0x800 else v


def _reg(n: int) -> str:
    return REGS_GENERAL[n]


def _fr(n: int) -> str:
    return REGS_FR[n]


def _dr(n: int) -> str:
    return REGS_DR[n >> 1]


def _fv(n: int) -> str:
    return REGS_FV[n >> 2]


_CTRL = {0: "sr", 1: "gbr", 2: "vbr", 3: "ssr", 4: "spc"}
_SYS = {0: "mach", 1: "macl", 2: "pr", 5: "fpul", 6: "fpscr"}


def _s(insn, mnem, ops, branch=BranchKind.NONE, delay=False, target=None):
    insn.mnemonic = mnem
    insn.operands = ops
    insn.branch = branch
    insn.has_delay_slot = delay
    insn.branch_target = target


def _R(n):
    return Operand(type=OperandType.REG, reg=_reg(n))


def _I(v):
    return Operand(type=OperandType.IMM, imm=v)


def _CR(name):
    return Operand(type=OperandType.CTRL_REG, reg=name)


def _SR(name):
    return Operand(type=OperandType.SYS_REG, reg=name)


def _FR(n):
    return Operand(type=OperandType.FR_REG, reg=_fr(n))


def _DR(n):
    return Operand(type=OperandType.DR_REG, reg=_dr(n & 0xE))


def _FV(n):
    return Operand(type=OperandType.FV_REG, reg=_fv(n))


def _AT(n, sz=None):
    return Operand(type=OperandType.AT_REG, reg=_reg(n), size=sz)


def _ATP(n, sz=4):
    return Operand(type=OperandType.AT_REG_POST, reg=_reg(n), size=sz)


def _ATM(n, sz=4):
    return Operand(type=OperandType.AT_PRE_REG, reg=_reg(n), size=sz)


def _AR0(n, sz):
    return Operand(type=OperandType.AT_R0_REG, reg=_reg(n), size=sz)


def _ADDR(a):
    return Operand(type=OperandType.ADDR, addr=a)


def _DPC(a, sz):
    return Operand(type=OperandType.DISP_PC, addr=a, size=sz)


def _DREG(n, disp, sz):
    return Operand(type=OperandType.DISP_REG, reg=_reg(n), disp=disp, size=sz)


def _DGBR(disp, sz):
    return Operand(type=OperandType.DISP_GBR, disp=disp, size=sz)


def _R0GBR(sz):
    return Operand(type=OperandType.AT_R0_GBR, size=sz)


# ---------------------------------------------------------------------------
# Group decoders
# ---------------------------------------------------------------------------

def _g0(insn, raw, n, m, d):
    lo = raw & 0xFF
    if d == 4:
        _s(insn, "mov.b", [_R(m), _AR0(n, 1)])
    elif d == 5:
        _s(insn, "mov.w", [_R(m), _AR0(n, 2)])
    elif d == 6:
        _s(insn, "mov.l", [_R(m), _AR0(n, 4)])
    elif d == 7:
        _s(insn, "mul.l", [_R(m), _R(n)])
    elif d == 0xC:
        _s(insn, "mov.b", [_AR0(m, 1), _R(n)])
    elif d == 0xD:
        _s(insn, "mov.w", [_AR0(m, 2), _R(n)])
    elif d == 0xE:
        _s(insn, "mov.l", [_AR0(m, 4), _R(n)])
    elif d == 0xF:
        _s(insn, "mac.l", [_ATP(m, 4), _ATP(n, 4)])
    elif d == 3:
        if m == 0:
            _s(insn, "bsrf", [_R(n)], BranchKind.CALL_REG_DIRECT, True)
        elif m == 2:
            _s(insn, "braf", [_R(n)], BranchKind.UNCOND_INDIRECT, True)
        elif m == 8:
            _s(insn, "pref", [_AT(n)])
        elif m == 9:
            _s(insn, "ocbi", [_AT(n)])
        elif m == 0xA:
            _s(insn, "ocbp", [_AT(n)])
        elif m == 0xB:
            _s(insn, "ocbwb", [_AT(n)])
        elif m == 0xC:
            _s(insn, "movca.l", [_R(0), _AT(n, 4)])
    elif d == 2:
        if m >= 8:
            _s(insn, "stc", [Operand(type=OperandType.REG, reg=REGS_BANKED[m & 7]), _R(n)])
        elif m in _CTRL:
            _s(insn, "stc", [_CR(_CTRL[m]), _R(n)])
    elif d == 0xA:
        if m == 3:
            _s(insn, "stc", [_CR("sgr"), _R(n)])
        elif m == 0xF:
            _s(insn, "stc", [_CR("dbr"), _R(n)])
        elif m in _SYS:
            _s(insn, "sts", [_SR(_SYS[m]), _R(n)])
    elif d == 9:
        if lo == 0x09:
            _s(insn, "nop", [])
        elif lo == 0x19:
            _s(insn, "div0u", [])
        elif m == 2:
            _s(insn, "movt", [_R(n)])
    elif d == 8:
        if lo == 0x08:
            _s(insn, "clrt", [])
        elif lo == 0x18:
            _s(insn, "sett", [])
        elif lo == 0x28:
            _s(insn, "clrmac", [])
        elif lo == 0x38:
            _s(insn, "ldtlb", [])
        elif lo == 0x48:
            _s(insn, "clrs", [])
        elif lo == 0x58:
            _s(insn, "sets", [])
    elif d == 0xB:
        if raw == 0x000B:
            _s(insn, "rts", [], BranchKind.RETURN, True)
        elif raw == 0x001B:
            _s(insn, "sleep", [])
        elif raw == 0x002B:
            _s(insn, "rte", [], BranchKind.EXCEPTION_RETURN, True)


def _g2(insn, n, m, d):
    if d == 0:
        _s(insn, "mov.b", [_R(m), _AT(n, 1)])
    elif d == 1:
        _s(insn, "mov.w", [_R(m), _AT(n, 2)])
    elif d == 2:
        _s(insn, "mov.l", [_R(m), _AT(n, 4)])
    elif d == 4:
        _s(insn, "mov.b", [_R(m), _ATM(n, 1)])
    elif d == 5:
        _s(insn, "mov.w", [_R(m), _ATM(n, 2)])
    elif d == 6:
        _s(insn, "mov.l", [_R(m), _ATM(n, 4)])
    elif d == 7:
        _s(insn, "div0s", [_R(m), _R(n)])
    elif d == 8:
        _s(insn, "tst", [_R(m), _R(n)])
    elif d == 9:
        _s(insn, "and", [_R(m), _R(n)])
    elif d == 0xA:
        _s(insn, "xor", [_R(m), _R(n)])
    elif d == 0xB:
        _s(insn, "or", [_R(m), _R(n)])
    elif d == 0xC:
        _s(insn, "cmp/str", [_R(m), _R(n)])
    elif d == 0xD:
        _s(insn, "xtrct", [_R(m), _R(n)])
    elif d == 0xE:
        _s(insn, "mulu.w", [_R(m), _R(n)])
    elif d == 0xF:
        _s(insn, "muls.w", [_R(m), _R(n)])
    elif d == 3:
        pass  # invalid


def _g3(insn, n, m, d):
    if d == 0:
        _s(insn, "cmp/eq", [_R(m), _R(n)])
    elif d == 2:
        _s(insn, "cmp/hs", [_R(m), _R(n)])
    elif d == 3:
        _s(insn, "cmp/ge", [_R(m), _R(n)])
    elif d == 4:
        _s(insn, "div1", [_R(m), _R(n)])
    elif d == 5:
        _s(insn, "dmulu.l", [_R(m), _R(n)])
    elif d == 6:
        _s(insn, "cmp/hi", [_R(m), _R(n)])
    elif d == 7:
        _s(insn, "cmp/gt", [_R(m), _R(n)])
    elif d == 8:
        _s(insn, "sub", [_R(m), _R(n)])
    elif d == 0xA:
        _s(insn, "subc", [_R(m), _R(n)])
    elif d == 0xB:
        _s(insn, "subv", [_R(m), _R(n)])
    elif d == 0xC:
        _s(insn, "add", [_R(m), _R(n)])
    elif d == 0xD:
        _s(insn, "dmuls.l", [_R(m), _R(n)])
    elif d == 0xE:
        _s(insn, "addc", [_R(m), _R(n)])
    elif d == 0xF:
        _s(insn, "addv", [_R(m), _R(n)])


def _g4(insn, raw, n, m, d, addr):
    lo = raw & 0xFF
    if lo == 0x00:
        _s(insn, "shll", [_R(n)])
    elif lo == 0x01:
        _s(insn, "shlr", [_R(n)])
    elif lo == 0x02:
        _s(insn, "sts.l", [_SR("mach"), _ATM(n, 4)])
    elif lo == 0x03:
        _s(insn, "stc.l", [_CR("sr"), _ATM(n, 4)])
    elif lo == 0x04:
        _s(insn, "rotl", [_R(n)])
    elif lo == 0x05:
        _s(insn, "rotr", [_R(n)])
    elif lo == 0x06:
        _s(insn, "lds.l", [_ATP(n, 4), _SR("mach")])
    elif lo == 0x07:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("sr")])
    elif lo == 0x08:
        _s(insn, "shll2", [_R(n)])
    elif lo == 0x09:
        _s(insn, "shlr2", [_R(n)])
    elif lo == 0x0A:
        _s(insn, "lds", [_R(n), _SR("mach")])
    elif lo == 0x0B:
        _s(insn, "jsr", [_AT(n)], BranchKind.CALL_INDIRECT, True)
    elif lo == 0x0E:
        _s(insn, "ldc", [_R(n), _CR("sr")])
    elif lo == 0x10:
        _s(insn, "dt", [_R(n)])
    elif lo == 0x11:
        _s(insn, "cmp/pz", [_R(n)])
    elif lo == 0x12:
        _s(insn, "sts.l", [_SR("macl"), _ATM(n, 4)])
    elif lo == 0x13:
        _s(insn, "stc.l", [_CR("gbr"), _ATM(n, 4)])
    elif lo == 0x14:
        pass  # invalid
    elif lo == 0x15:
        _s(insn, "cmp/pl", [_R(n)])
    elif lo == 0x16:
        _s(insn, "lds.l", [_ATP(n, 4), _SR("macl")])
    elif lo == 0x17:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("gbr")])
    elif lo == 0x18:
        _s(insn, "shll8", [_R(n)])
    elif lo == 0x19:
        _s(insn, "shlr8", [_R(n)])
    elif lo == 0x1A:
        _s(insn, "lds", [_R(n), _SR("macl")])
    elif lo == 0x1B:
        _s(insn, "tas.b", [_AT(n, 1)])
    elif lo == 0x1E:
        _s(insn, "ldc", [_R(n), _CR("gbr")])
    elif lo == 0x20:
        _s(insn, "shal", [_R(n)])
    elif lo == 0x21:
        _s(insn, "shar", [_R(n)])
    elif lo == 0x22:
        _s(insn, "sts.l", [_SR("pr"), _ATM(n, 4)])
    elif lo == 0x23:
        _s(insn, "stc.l", [_CR("vbr"), _ATM(n, 4)])
    elif lo == 0x24:
        _s(insn, "rotcl", [_R(n)])
    elif lo == 0x25:
        _s(insn, "rotcr", [_R(n)])
    elif lo == 0x26:
        _s(insn, "lds.l", [_ATP(n, 4), _SR("pr")])
    elif lo == 0x27:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("vbr")])
    elif lo == 0x28:
        _s(insn, "shll16", [_R(n)])
    elif lo == 0x29:
        _s(insn, "shlr16", [_R(n)])
    elif lo == 0x2A:
        _s(insn, "lds", [_R(n), _SR("pr")])
    elif lo == 0x2B:
        _s(insn, "jmp", [_AT(n)], BranchKind.UNCOND_INDIRECT, True)
    elif lo == 0x2E:
        _s(insn, "ldc", [_R(n), _CR("vbr")])
    elif lo == 0x33:
        _s(insn, "stc.l", [_CR("ssr"), _ATM(n, 4)])
    elif lo == 0x37:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("ssr")])
    elif lo == 0x3E:
        _s(insn, "ldc", [_R(n), _CR("ssr")])
    elif lo == 0x43:
        _s(insn, "stc.l", [_CR("spc"), _ATM(n, 4)])
    elif lo == 0x47:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("spc")])
    elif lo == 0x4E:
        _s(insn, "ldc", [_R(n), _CR("spc")])
    elif lo == 0x52:
        _s(insn, "sts.l", [_SR("fpul"), _ATM(n, 4)])
    elif lo == 0x56:
        _s(insn, "lds.l", [_ATP(n, 4), _SR("fpul")])
    elif lo == 0x5A:
        _s(insn, "lds", [_R(n), _SR("fpul")])
    elif lo == 0x62:
        _s(insn, "sts.l", [_SR("fpscr"), _ATM(n, 4)])
    elif lo == 0x66:
        _s(insn, "lds.l", [_ATP(n, 4), _SR("fpscr")])
    elif lo == 0x6A:
        _s(insn, "lds", [_R(n), _SR("fpscr")])
    elif lo == 0x32:
        _s(insn, "stc.l", [_CR("sgr"), _ATM(n, 4)])
    elif lo == 0x36:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("sgr")])
    elif lo == 0xF2:
        _s(insn, "stc.l", [_CR("dbr"), _ATM(n, 4)])
    elif lo == 0xF6:
        _s(insn, "ldc.l", [_ATP(n, 4), _CR("dbr")])
    elif lo == 0xFA:
        _s(insn, "ldc", [_R(n), _CR("dbr")])
    elif lo == 0x3A:
        _s(insn, "ldc", [_R(n), _CR("sgr")])
    elif d == 0xC:
        _s(insn, "shad", [_R(m), _R(n)])
    elif d == 0xD:
        _s(insn, "shld", [_R(m), _R(n)])
    elif d == 0xF:
        _s(insn, "mac.w", [_ATP(m, 2), _ATP(n, 2)])
    else:
        # Banked STC.L / LDC.L / LDC
        if (lo & 0x0F) == 0x03 and m >= 8:
            _s(insn, "stc.l", [Operand(type=OperandType.REG, reg=REGS_BANKED[m & 7]), _ATM(n, 4)])
        elif (lo & 0x0F) == 0x07 and m >= 8:
            _s(insn, "ldc.l", [_ATP(n, 4), Operand(type=OperandType.REG, reg=REGS_BANKED[m & 7])])
        elif (lo & 0x0F) == 0x0E and m >= 8:
            _s(insn, "ldc", [_R(n), Operand(type=OperandType.REG, reg=REGS_BANKED[m & 7])])


def _g6(insn, n, m, d):
    if d == 0:
        _s(insn, "mov.b", [_AT(m, 1), _R(n)])
    elif d == 1:
        _s(insn, "mov.w", [_AT(m, 2), _R(n)])
    elif d == 2:
        _s(insn, "mov.l", [_AT(m, 4), _R(n)])
    elif d == 3:
        _s(insn, "mov", [_R(m), _R(n)])
    elif d == 4:
        _s(insn, "mov.b", [_ATP(m, 1), _R(n)])
    elif d == 5:
        _s(insn, "mov.w", [_ATP(m, 2), _R(n)])
    elif d == 6:
        _s(insn, "mov.l", [_ATP(m, 4), _R(n)])
    elif d == 7:
        _s(insn, "not", [_R(m), _R(n)])
    elif d == 8:
        _s(insn, "swap.b", [_R(m), _R(n)])
    elif d == 9:
        _s(insn, "swap.w", [_R(m), _R(n)])
    elif d == 0xA:
        _s(insn, "negc", [_R(m), _R(n)])
    elif d == 0xB:
        _s(insn, "neg", [_R(m), _R(n)])
    elif d == 0xC:
        _s(insn, "extu.b", [_R(m), _R(n)])
    elif d == 0xD:
        _s(insn, "extu.w", [_R(m), _R(n)])
    elif d == 0xE:
        _s(insn, "exts.b", [_R(m), _R(n)])
    elif d == 0xF:
        _s(insn, "exts.w", [_R(m), _R(n)])


def _g8(insn, raw, addr):
    op = (raw >> 8) & 0xF
    rn = (raw >> 4) & 0xF  # for load/store: Rm or Rn depending on direction
    d4 = raw & 0xF
    d8 = raw & 0xFF
    if op == 0:
        _s(insn, "mov.b", [_R(0), _DREG(rn, d4, 1)])
    elif op == 1:
        _s(insn, "mov.w", [_R(0), _DREG(rn, d4 * 2, 2)])
    elif op == 4:
        _s(insn, "mov.b", [_DREG(rn, d4, 1), _R(0)])
    elif op == 5:
        _s(insn, "mov.w", [_DREG(rn, d4 * 2, 2), _R(0)])
    elif op == 8:
        _s(insn, "cmp/eq", [_I(_se8(d8)), _R(0)])
    elif op == 9:
        target = addr + 4 + _se8(d8) * 2
        _s(insn, "bt", [_ADDR(target)], BranchKind.COND_TRUE, target=target)
    elif op == 0xB:
        target = addr + 4 + _se8(d8) * 2
        _s(insn, "bf", [_ADDR(target)], BranchKind.COND_FALSE, target=target)
    elif op == 0xD:
        target = addr + 4 + _se8(d8) * 2
        _s(insn, "bt/s", [_ADDR(target)], BranchKind.COND_TRUE, True, target)
    elif op == 0xF:
        target = addr + 4 + _se8(d8) * 2
        _s(insn, "bf/s", [_ADDR(target)], BranchKind.COND_FALSE, True, target)


def _gC(insn, raw, addr):
    op = (raw >> 8) & 0xF
    imm = raw & 0xFF
    if op == 0:
        _s(insn, "mov.b", [_R(0), _DGBR(imm, 1)])
    elif op == 1:
        _s(insn, "mov.w", [_R(0), _DGBR(imm * 2, 2)])
    elif op == 2:
        _s(insn, "mov.l", [_R(0), _DGBR(imm * 4, 4)])
    elif op == 3:
        _s(insn, "trapa", [_I(imm)], BranchKind.SYSCALL)
    elif op == 4:
        _s(insn, "mov.b", [_DGBR(imm, 1), _R(0)])
    elif op == 5:
        _s(insn, "mov.w", [_DGBR(imm * 2, 2), _R(0)])
    elif op == 6:
        _s(insn, "mov.l", [_DGBR(imm * 4, 4), _R(0)])
    elif op == 7:
        target = (addr & ~3) + 4 + imm * 4
        _s(insn, "mova", [_ADDR(target), _R(0)])
    elif op == 8:
        _s(insn, "tst", [_I(imm), _R(0)])
    elif op == 9:
        _s(insn, "and", [_I(imm), _R(0)])
    elif op == 0xA:
        _s(insn, "xor", [_I(imm), _R(0)])
    elif op == 0xB:
        _s(insn, "or", [_I(imm), _R(0)])
    elif op == 0xC:
        _s(insn, "tst.b", [_I(imm), _R0GBR(1)])
    elif op == 0xD:
        _s(insn, "and.b", [_I(imm), _R0GBR(1)])
    elif op == 0xE:
        _s(insn, "xor.b", [_I(imm), _R0GBR(1)])
    elif op == 0xF:
        _s(insn, "or.b", [_I(imm), _R0GBR(1)])


def _gF(insn, raw, n, m, d):
    # FPU instructions: 1111nnnnmmmmdddd
    if d == 0:
        _s(insn, "fadd", [_FR(m), _FR(n)])
    elif d == 1:
        _s(insn, "fsub", [_FR(m), _FR(n)])
    elif d == 2:
        _s(insn, "fmul", [_FR(m), _FR(n)])
    elif d == 3:
        _s(insn, "fdiv", [_FR(m), _FR(n)])
    elif d == 4:
        _s(insn, "fcmp/eq", [_FR(m), _FR(n)])
    elif d == 5:
        _s(insn, "fcmp/gt", [_FR(m), _FR(n)])
    elif d == 6:
        # FMOV @(R0,Rm),FRn
        _s(insn, "fmov", [_AR0(m, 4), _FR(n)])
    elif d == 7:
        # FMOV FRm,@(R0,Rn)
        _s(insn, "fmov", [_FR(m), _AR0(n, 4)])
    elif d == 8:
        # FMOV @Rm,FRn
        _s(insn, "fmov", [_AT(m, 4), _FR(n)])
    elif d == 9:
        # FMOV @Rm+,FRn
        _s(insn, "fmov", [_ATP(m, 4), _FR(n)])
    elif d == 0xA:
        # FMOV FRm,@Rn
        _s(insn, "fmov", [_FR(m), _AT(n, 4)])
    elif d == 0xB:
        # FMOV FRm,@-Rn
        _s(insn, "fmov", [_FR(m), _ATM(n, 4)])
    elif d == 0xC:
        # FMOV FRm,FRn
        _s(insn, "fmov", [_FR(m), _FR(n)])
    elif d == 0xD:
        # Various single-operand FPU ops based on low bits of m
        lo = (raw >> 4) & 0xF
        if lo == 0:
            _s(insn, "fsts", [_SR("fpul"), _FR(n)])
        elif lo == 1:
            _s(insn, "flds", [_FR(n), _SR("fpul")])
        elif lo == 2:
            _s(insn, "float", [_SR("fpul"), _FR(n)])
        elif lo == 3:
            _s(insn, "ftrc", [_FR(n), _SR("fpul")])
        elif lo == 4:
            _s(insn, "fneg", [_FR(n)])
        elif lo == 5:
            _s(insn, "fabs", [_FR(n)])
        elif lo == 6:
            _s(insn, "fsqrt", [_FR(n)])
        elif lo == 7:
            _s(insn, "fsrra", [_FR(n)])
        elif lo == 8:
            _s(insn, "fldi0", [_FR(n)])
        elif lo == 9:
            _s(insn, "fldi1", [_FR(n)])
        elif lo == 0xA:
            _s(insn, "fcnvsd", [_SR("fpul"), _DR(n)])
        elif lo == 0xB:
            _s(insn, "fcnvds", [_DR(n), _SR("fpul")])
        elif lo == 0xE:
            _s(insn, "fipr", [_FV(m & 0xC), _FV(n & 0xC)])
        elif lo == 0xF:
            if n == 3:
                _s(insn, "fschg", [])
            elif n == 0xB:
                _s(insn, "frchg", [])
            elif (n & 1) == 1:
                _s(insn, "ftrv", [
                    Operand(type=OperandType.XMTRX, reg="xmtrx"),
                    _FV(n & 0xC),
                ])
        elif lo == 0xD:
            _s(insn, "fsca", [_SR("fpul"), _DR(n)])
    elif d == 0xE:
        _s(insn, "fmac", [_FR(0), _FR(m), _FR(n)])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decode(data: bytes, addr: int) -> Optional[SH4Instruction]:
    """Decode a single SH-4 instruction.

    *data* must contain at least 2 bytes.  Returns a fully populated
    `SH4Instruction` or ``None`` if *data* is too short.
    """
    if len(data) < 2:
        return None

    raw = struct.unpack_from('<H', data, 0)[0]
    top = (raw >> 12) & 0xF
    n = (raw >> 8) & 0xF
    m = (raw >> 4) & 0xF
    d = raw & 0xF

    insn = SH4Instruction(mnemonic=".word", raw=raw, addr=addr,
                          operands=[_I(raw)])

    if top == 0x0:
        _g0(insn, raw, n, m, d)
    elif top == 0x1:
        # MOV.L Rm,@(disp,Rn)
        _s(insn, "mov.l", [_R(m), _DREG(n, d * 4, 4)])
    elif top == 0x2:
        _g2(insn, n, m, d)
    elif top == 0x3:
        _g3(insn, n, m, d)
    elif top == 0x4:
        _g4(insn, raw, n, m, d, addr)
    elif top == 0x5:
        # MOV.L @(disp,Rm),Rn
        _s(insn, "mov.l", [_DREG(m, d * 4, 4), _R(n)])
    elif top == 0x6:
        _g6(insn, n, m, d)
    elif top == 0x7:
        # ADD #imm,Rn
        _s(insn, "add", [_I(_se8(raw & 0xFF)), _R(n)])
    elif top == 0x8:
        _g8(insn, raw, addr)
    elif top == 0x9:
        # MOV.W @(disp,PC),Rn
        d8 = raw & 0xFF
        target = addr + 4 + d8 * 2
        _s(insn, "mov.w", [_DPC(target, 2), _R(n)])
    elif top == 0xA:
        # BRA disp12
        d12 = _se12(raw & 0xFFF)
        target = addr + 4 + d12 * 2
        _s(insn, "bra", [_ADDR(target)], BranchKind.UNCOND_DIRECT, True, target)
    elif top == 0xB:
        # BSR disp12
        d12 = _se12(raw & 0xFFF)
        target = addr + 4 + d12 * 2
        _s(insn, "bsr", [_ADDR(target)], BranchKind.CALL_DIRECT, True, target)
    elif top == 0xC:
        _gC(insn, raw, addr)
    elif top == 0xD:
        # MOV.L @(disp,PC),Rn
        d8 = raw & 0xFF
        target = (addr & ~3) + 4 + d8 * 4
        _s(insn, "mov.l", [_DPC(target, 4), _R(n)])
    elif top == 0xE:
        # MOV #imm,Rn
        _s(insn, "mov", [_I(_se8(raw & 0xFF)), _R(n)])
    elif top == 0xF:
        _gF(insn, raw, n, m, d)

    return insn


# ---------------------------------------------------------------------------
# Disassembly text tokens
# ---------------------------------------------------------------------------

_T = InstructionTextTokenType


def _tok_operand(op: Operand, tokens: list) -> None:
    """Append tokens for a single operand."""
    t = op.type
    if t == OperandType.REG or t == OperandType.CTRL_REG or t == OperandType.SYS_REG:
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
    elif t == OperandType.FR_REG or t == OperandType.DR_REG or t == OperandType.XD_REG:
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
    elif t == OperandType.FV_REG:
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
    elif t == OperandType.XMTRX:
        tokens.append(InstructionTextToken(_T.RegisterToken, "xmtrx"))
    elif t == OperandType.IMM:
        v = op.imm
        if -128 <= v <= 255:
            tokens.append(InstructionTextToken(_T.IntegerToken, f"#0x{v & 0xFF:x}", v & 0xFFFFFFFF))
        else:
            tokens.append(InstructionTextToken(_T.IntegerToken, f"#0x{v & 0xFFFFFFFF:x}", v & 0xFFFFFFFF))
    elif t == OperandType.ADDR:
        tokens.append(InstructionTextToken(_T.PossibleAddressToken, f"0x{op.addr:x}", op.addr))
    elif t == OperandType.DISP_PC:
        tokens.append(InstructionTextToken(_T.PossibleAddressToken, f"0x{op.addr:x}", op.addr))
    elif t == OperandType.DISP_REG:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@("))
        tokens.append(InstructionTextToken(_T.IntegerToken, f"0x{op.disp:x}", op.disp))
        tokens.append(InstructionTextToken(_T.TextToken, ","))
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, ")"))
    elif t == OperandType.DISP_GBR:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@("))
        tokens.append(InstructionTextToken(_T.IntegerToken, f"0x{op.disp:x}", op.disp))
        tokens.append(InstructionTextToken(_T.TextToken, ","))
        tokens.append(InstructionTextToken(_T.RegisterToken, "gbr"))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, ")"))
    elif t == OperandType.AT_REG:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@"))
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, ""))
    elif t == OperandType.AT_REG_POST:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@"))
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, "+"))
    elif t == OperandType.AT_PRE_REG:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@-"))
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, ""))
    elif t == OperandType.AT_R0_REG:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@("))
        tokens.append(InstructionTextToken(_T.RegisterToken, "r0"))
        tokens.append(InstructionTextToken(_T.TextToken, ","))
        tokens.append(InstructionTextToken(_T.RegisterToken, op.reg))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, ")"))
    elif t == OperandType.AT_R0_GBR:
        tokens.append(InstructionTextToken(_T.BeginMemoryOperandToken, "@("))
        tokens.append(InstructionTextToken(_T.RegisterToken, "r0"))
        tokens.append(InstructionTextToken(_T.TextToken, ","))
        tokens.append(InstructionTextToken(_T.RegisterToken, "gbr"))
        tokens.append(InstructionTextToken(_T.EndMemoryOperandToken, ")"))


def get_text_tokens(insn: SH4Instruction) -> List[InstructionTextToken]:
    """Return Binary Ninja InstructionTextTokens for display."""
    tokens: List[InstructionTextToken] = []

    # Mnemonic
    tokens.append(InstructionTextToken(_T.InstructionToken, insn.mnemonic))

    for i, op in enumerate(insn.operands):
        if i == 0:
            tokens.append(InstructionTextToken(_T.OperandSeparatorToken, "  "))
        else:
            tokens.append(InstructionTextToken(_T.OperandSeparatorToken, ","))
        _tok_operand(op, tokens)

    return tokens


# ---------------------------------------------------------------------------
# Instruction info (branches + length)
# ---------------------------------------------------------------------------

def get_info(insn: SH4Instruction) -> InstructionInfo:
    """Return Binary Ninja InstructionInfo with branch edges.

    Delay-slot branches consume 4 bytes (branch + slot) so BN never sees
    the slot instruction as a standalone IL statement.  We do NOT set
    branch_delay; the lifter reorders slot/branch itself.
    """
    info = InstructionInfo()
    info.length = 4 if insn.has_delay_slot else 2

    b = insn.branch
    if b == BranchKind.NONE:
        pass
    elif b == BranchKind.UNCOND_DIRECT:
        if insn.branch_target is not None:
            info.add_branch(BranchType.UnconditionalBranch, insn.branch_target)
    elif b == BranchKind.UNCOND_INDIRECT:
        info.add_branch(BranchType.UnresolvedBranch)
    elif b == BranchKind.COND_TRUE or b == BranchKind.COND_FALSE:
        if insn.branch_target is not None:
            info.add_branch(BranchType.TrueBranch, insn.branch_target)
            # Fallthrough is the next instruction. bt/bf are 2 bytes;
            # bt/s and bf/s are 4 (branch + delay slot). info.length
            # already encodes this, so use it rather than a fixed +4.
            info.add_branch(BranchType.FalseBranch, insn.addr + info.length)
    elif b == BranchKind.CALL_DIRECT:
        if insn.branch_target is not None:
            info.add_branch(BranchType.CallDestination, insn.branch_target)
    elif b == BranchKind.CALL_INDIRECT:
        pass  # IL emits il.call(reg); BN infers fallthrough from that
    elif b == BranchKind.CALL_REG_DIRECT:
        pass  # IL emits il.call(computed); BN infers fallthrough from that
    elif b == BranchKind.RETURN:
        info.add_branch(BranchType.FunctionReturn)
    elif b == BranchKind.EXCEPTION_RETURN:
        info.add_branch(BranchType.FunctionReturn)
    elif b == BranchKind.SYSCALL:
        info.add_branch(BranchType.SystemCall)

    return info
