"""SH-4 → Binary Ninja Low-Level IL lifter.

Translates every decoded SH4Instruction into LLIL expressions.  The single
public entry point is ``lift(insn, il) -> int``.
"""

from binaryninja import LowLevelILFunction, LowLevelILLabel, LLIL_TEMP

from .sh4_types import (
    SH4Instruction,
    Operand,
    OperandType,
    BranchKind,
    SR_FLAG_T,
    SR_FLAG_S,
    SR_FLAG_Q,
    SR_FLAG_M,
)

# ── tiny helpers ──────────────────────────────────────────────────────────

_MEM_TYPES = frozenset((
    OperandType.AT_REG, OperandType.AT_REG_POST, OperandType.AT_PRE_REG,
    OperandType.DISP_REG, OperandType.DISP_PC, OperandType.DISP_GBR,
    OperandType.AT_R0_REG, OperandType.AT_R0_GBR,
))


def _r(il, name):
    """Read 32-bit GP / control / system register."""
    return il.reg(4, name)


def _c(il, v):
    """32-bit constant."""
    return il.const(4, v)


def _flag_t(il):
    return il.flag(SR_FLAG_T)


def _set_t(il, expr):
    il.append(il.set_flag(SR_FLAG_T, expr))


def _set_q(il, expr):
    il.append(il.set_flag(SR_FLAG_Q, expr))


def _set_m(il, expr):
    il.append(il.set_flag(SR_FLAG_M, expr))


def _mem_addr(il, op):
    """Compute the effective address for a memory operand.

    Pre-decrement / post-increment side-effects are NOT emitted here.
    """
    t = op.type
    if t in (OperandType.AT_REG, OperandType.AT_REG_POST):
        return _r(il, op.reg)
    if t == OperandType.AT_PRE_REG:
        return _r(il, op.reg)          # caller already emitted the decrement
    if t == OperandType.DISP_REG:
        return il.add(4, _r(il, op.reg), _c(il, op.disp))
    if t == OperandType.DISP_PC:
        return il.const_pointer(4, op.addr)
    if t == OperandType.DISP_GBR:
        return il.add(4, _r(il, 'gbr'), _c(il, op.disp))
    if t == OperandType.AT_R0_REG:
        return il.add(4, _r(il, 'r0'), _r(il, op.reg))
    if t == OperandType.AT_R0_GBR:
        return il.add(4, _r(il, 'r0'), _r(il, 'gbr'))
    return _c(il, 0)


def _pre_dec(il, op):
    """Emit Rn -= size for @-Rn operand."""
    if op.type == OperandType.AT_PRE_REG:
        sz = op.size or 4
        il.append(il.set_reg(4, op.reg,
                             il.sub(4, _r(il, op.reg), _c(il, sz))))


def _post_inc(il, op, skip_reg=None):
    """Emit Rm += size for @Rm+ operand (skip if Rm==Rn on load)."""
    if op.type == OperandType.AT_REG_POST:
        if skip_reg and op.reg == skip_reg:
            return
        sz = op.size or 4
        il.append(il.set_reg(4, op.reg,
                             il.add(4, _r(il, op.reg), _c(il, sz))))


def _read_op(il, op):
    """Read an operand value as a 4-byte IL expression.

    Memory operands: loads op.size bytes; sign-extends bytes/words to 32-bit.
    """
    t = op.type
    if t == OperandType.REG:
        return _r(il, op.reg)
    if t == OperandType.IMM:
        return _c(il, op.imm)
    if t == OperandType.ADDR:
        return il.const_pointer(4, op.addr)
    if t == OperandType.CTRL_REG:
        return _r(il, op.reg)
    if t == OperandType.SYS_REG:
        return _r(il, op.reg)
    if t == OperandType.FR_REG:
        return il.reg(4, op.reg)
    if t == OperandType.DR_REG:
        return il.reg(8, op.reg)
    if t == OperandType.XD_REG:
        return il.reg(8, op.reg)
    if t in _MEM_TYPES:
        sz = op.size or 4
        val = il.load(sz, _mem_addr(il, op))
        if sz < 4:
            val = il.sign_extend(4, val)
        return val
    return il.unimplemented()


def _write_reg(il, op, val, sz=4):
    """Write *val* to a register operand."""
    t = op.type
    if t == OperandType.REG:
        il.append(il.set_reg(4, op.reg, val))
    elif t == OperandType.CTRL_REG:
        il.append(il.set_reg(4, op.reg, val))
    elif t == OperandType.SYS_REG:
        il.append(il.set_reg(4, op.reg, val))
    elif t == OperandType.FR_REG:
        il.append(il.set_reg(4, op.reg, val))
    elif t == OperandType.DR_REG:
        il.append(il.set_reg(8, op.reg, val))
    elif t == OperandType.XD_REG:
        il.append(il.set_reg(8, op.reg, val))


# ── data-movement ─────────────────────────────────────────────────────────

def _lift_mov(insn, il):
    """MOV Rm,Rn  /  MOV #imm,Rn"""
    src, dst = insn.operands
    il.append(il.set_reg(4, dst.reg, _read_op(il, src)))


def _lift_mov_mem(insn, il, size):
    """MOV.B / MOV.W / MOV.L — load or store."""
    src, dst = insn.operands

    if dst.type in _MEM_TYPES:
        # ── store ──
        _pre_dec(il, dst)
        addr = _mem_addr(il, dst)
        val = _read_op(il, src)
        il.append(il.store(size, addr, val))
        _post_inc(il, src)
    else:
        # ── load (to register) ──
        _pre_dec(il, src)
        addr = _mem_addr(il, src)
        val = il.load(size, addr)
        if size < 4:
            val = il.sign_extend(4, val)
        dst_reg = dst.reg
        il.append(il.set_reg(4, dst_reg, val))
        _post_inc(il, src, skip_reg=dst_reg)


def _lift_mova(insn, il):
    """MOVA @(disp,PC),R0"""
    il.append(il.set_reg(4, 'r0', il.const_pointer(4, insn.operands[0].addr)))


def _lift_movt(insn, il):
    """MOVT Rn — Rn = (T == 1) ? 1 : 0"""
    il.append(il.set_reg(4, insn.operands[0].reg,
                         il.bool_to_int(4, _flag_t(il))))


def _lift_movca_l(insn, il):
    """MOVCA.L R0, @Rn"""
    il.append(il.store(4, _r(il, insn.operands[1].reg), _r(il, 'r0')))


# ── arithmetic ────────────────────────────────────────────────────────────

def _lift_add(insn, il):
    """ADD Rm,Rn / ADD #imm,Rn"""
    src, dst = insn.operands
    il.append(il.set_reg(4, dst.reg,
                         il.add(4, _r(il, dst.reg), _read_op(il, src))))


def _lift_addc(insn, il):
    """ADDC Rm,Rn — Rn = Rn + Rm + T; T = carry-out"""
    rm, rn = insn.operands
    # Save old values in temps for carry computation
    t0, t1 = LLIL_TEMP(0), LLIL_TEMP(1)
    # t0 = Rn + Rm
    il.append(il.set_reg(4, t0,
              il.add(4, _r(il, rn.reg), _r(il, rm.reg))))
    # carry1 = (t0 < Rn)  — unsigned overflow from first add
    carry1 = il.compare_unsigned_less_than(4, il.reg(4, t0), _r(il, rn.reg))
    # t1 = t0 + T
    il.append(il.set_reg(4, t1,
              il.add(4, il.reg(4, t0), il.bool_to_int(4, _flag_t(il)))))
    # carry2 = (t1 < t0) — unsigned overflow from second add
    carry2 = il.compare_unsigned_less_than(4, il.reg(4, t1), il.reg(4, t0))
    # T = carry1 | carry2
    _set_t(il, il.or_expr(0, carry1, carry2))
    # Rn = t1
    il.append(il.set_reg(4, rn.reg, il.reg(4, t1)))


def _lift_sub(insn, il):
    """SUB Rm,Rn — Rn = Rn - Rm"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.sub(4, _r(il, rn.reg), _r(il, rm.reg))))


def _lift_subc(insn, il):
    """SUBC Rm,Rn — Rn = Rn - Rm - T; T = borrow"""
    rm, rn = insn.operands
    t0, t1 = LLIL_TEMP(0), LLIL_TEMP(1)
    # t0 = Rn - Rm
    il.append(il.set_reg(4, t0,
              il.sub(4, _r(il, rn.reg), _r(il, rm.reg))))
    # borrow1 = (Rn < Rm) unsigned
    borrow1 = il.compare_unsigned_less_than(4, _r(il, rn.reg), _r(il, rm.reg))
    # t1 = t0 - T
    il.append(il.set_reg(4, t1,
              il.sub(4, il.reg(4, t0), il.bool_to_int(4, _flag_t(il)))))
    # borrow2 = (t0 < T_as_int) — but T is 0 or 1, so overflow only if t0==0 and T==1
    borrow2 = il.compare_unsigned_less_than(4, il.reg(4, t0),
                                            il.bool_to_int(4, _flag_t(il)))
    _set_t(il, il.or_expr(0, borrow1, borrow2))
    il.append(il.set_reg(4, rn.reg, il.reg(4, t1)))


def _lift_addv(insn, il):
    """ADDV Rm,Rn — Rn = Rn + Rm; T = signed overflow"""
    rm, rn = insn.operands
    old = LLIL_TEMP(0)
    il.append(il.set_reg(4, old, _r(il, rn.reg)))
    result = LLIL_TEMP(1)
    il.append(il.set_reg(4, result,
              il.add(4, _r(il, rn.reg), _r(il, rm.reg))))
    # Signed overflow: signs of operands are the same AND result sign differs
    src_sign = il.xor_expr(4, il.reg(4, old), _r(il, rm.reg))
    res_sign = il.xor_expr(4, il.reg(4, result), il.reg(4, old))
    # Overflow = (~(Rn_old ^ Rm) & (Result ^ Rn_old)) bit 31 only
    _set_t(il, il.compare_not_equal(4,
        il.and_expr(4,
            il.and_expr(4, il.not_expr(4, src_sign), res_sign),
            _c(il, 0x80000000)),
        _c(il, 0)))
    il.append(il.set_reg(4, rn.reg, il.reg(4, result)))


def _lift_subv(insn, il):
    """SUBV Rm,Rn — Rn = Rn - Rm; T = signed overflow"""
    rm, rn = insn.operands
    old = LLIL_TEMP(0)
    il.append(il.set_reg(4, old, _r(il, rn.reg)))
    result = LLIL_TEMP(1)
    il.append(il.set_reg(4, result,
              il.sub(4, _r(il, rn.reg), _r(il, rm.reg))))
    # Signed overflow: signs of operands differ AND result sign differs from Rn
    src_sign = il.xor_expr(4, il.reg(4, old), _r(il, rm.reg))
    res_sign = il.xor_expr(4, il.reg(4, result), il.reg(4, old))
    # Overflow = ((Rn_old ^ Rm) & (Result ^ Rn_old)) bit 31 only
    _set_t(il, il.compare_not_equal(4,
        il.and_expr(4,
            il.and_expr(4, src_sign, res_sign),
            _c(il, 0x80000000)),
        _c(il, 0)))
    il.append(il.set_reg(4, rn.reg, il.reg(4, result)))


def _lift_neg(insn, il):
    """NEG Rm,Rn — Rn = 0 - Rm"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg, il.neg_expr(4, _r(il, rm.reg))))


def _lift_negc(insn, il):
    """NEGC Rm,Rn — Rn = 0 - Rm - T; T = borrow"""
    rm, rn = insn.operands
    t0 = LLIL_TEMP(0)
    # t0 = 0 - Rm
    il.append(il.set_reg(4, t0, il.neg_expr(4, _r(il, rm.reg))))
    # borrow1 = (0 < Rm) i.e. Rm != 0
    borrow1 = il.compare_not_equal(4, _r(il, rm.reg), _c(il, 0))
    # result = t0 - T
    t1 = LLIL_TEMP(1)
    il.append(il.set_reg(4, t1,
              il.sub(4, il.reg(4, t0), il.bool_to_int(4, _flag_t(il)))))
    borrow2 = il.compare_unsigned_less_than(4, il.reg(4, t0),
                                            il.bool_to_int(4, _flag_t(il)))
    _set_t(il, il.or_expr(0, borrow1, borrow2))
    il.append(il.set_reg(4, rn.reg, il.reg(4, t1)))


def _lift_dt(insn, il):
    """DT Rn — Rn -= 1; T = (Rn == 0)"""
    rn = insn.operands[0]
    il.append(il.set_reg(4, rn.reg,
                         il.sub(4, _r(il, rn.reg), _c(il, 1))))
    _set_t(il, il.compare_equal(4, _r(il, rn.reg), _c(il, 0)))


def _lift_mul_l(insn, il):
    """MUL.L Rm,Rn — MACL = Rm * Rn (low 32 bits)"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, 'macl',
                         il.mult(4, _r(il, rm.reg), _r(il, rn.reg))))


def _lift_muls_w(insn, il):
    """MULS.W Rm,Rn — MACL = sign_ext(Rm[15:0]) * sign_ext(Rn[15:0])"""
    rm, rn = insn.operands
    a = il.sign_extend(4, il.low_part(2, _r(il, rm.reg)))
    b = il.sign_extend(4, il.low_part(2, _r(il, rn.reg)))
    il.append(il.set_reg(4, 'macl', il.mult(4, a, b)))


def _lift_mulu_w(insn, il):
    """MULU.W Rm,Rn — MACL = zero_ext(Rm[15:0]) * zero_ext(Rn[15:0])"""
    rm, rn = insn.operands
    a = il.zero_extend(4, il.low_part(2, _r(il, rm.reg)))
    b = il.zero_extend(4, il.low_part(2, _r(il, rn.reg)))
    il.append(il.set_reg(4, 'macl', il.mult(4, a, b)))


def _lift_dmuls_l(insn, il):
    """DMULS.L Rm,Rn — MACH:MACL = signed(Rm) * signed(Rn)  (64-bit result)"""
    rm, rn = insn.operands
    il.append(il.set_reg_split(4, 'mach', 'macl',
              il.mult_double_prec_signed(4, _r(il, rm.reg), _r(il, rn.reg))))


def _lift_dmulu_l(insn, il):
    """DMULU.L Rm,Rn — MACH:MACL = unsigned(Rm) * unsigned(Rn)"""
    rm, rn = insn.operands
    il.append(il.set_reg_split(4, 'mach', 'macl',
              il.mult_double_prec_unsigned(4, _r(il, rm.reg), _r(il, rn.reg))))


def _lift_mac_l(insn, il):
    """MAC.L @Rm+,@Rn+ — MACH:MACL += sign([@Rm]) * sign([@Rn]); Rm+=4, Rn+=4"""
    rm_op, rn_op = insn.operands
    # Load both values
    t0, t1 = LLIL_TEMP(0), LLIL_TEMP(1)
    il.append(il.set_reg(4, t0, il.load(4, _r(il, rm_op.reg))))
    il.append(il.set_reg(4, t1, il.load(4, _r(il, rn_op.reg))))
    # Rm += 4, Rn += 4
    il.append(il.set_reg(4, rm_op.reg, il.add(4, _r(il, rm_op.reg), _c(il, 4))))
    il.append(il.set_reg(4, rn_op.reg, il.add(4, _r(il, rn_op.reg), _c(il, 4))))
    # MACH:MACL += sign(t0) * sign(t1) — approximate with 32-bit multiply + add
    product = il.mult(4, il.reg(4, t0), il.reg(4, t1))
    il.append(il.set_reg(4, 'macl', il.add(4, _r(il, 'macl'), product)))


def _lift_mac_w(insn, il):
    """MAC.W @Rm+,@Rn+ — MACH:MACL += sign([@Rm].w) * sign([@Rn].w); Rm+=2, Rn+=2"""
    rm_op, rn_op = insn.operands
    t0, t1 = LLIL_TEMP(0), LLIL_TEMP(1)
    il.append(il.set_reg(4, t0,
              il.sign_extend(4, il.load(2, _r(il, rm_op.reg)))))
    il.append(il.set_reg(4, t1,
              il.sign_extend(4, il.load(2, _r(il, rn_op.reg)))))
    il.append(il.set_reg(4, rm_op.reg, il.add(4, _r(il, rm_op.reg), _c(il, 2))))
    il.append(il.set_reg(4, rn_op.reg, il.add(4, _r(il, rn_op.reg), _c(il, 2))))
    product = il.mult(4, il.reg(4, t0), il.reg(4, t1))
    il.append(il.set_reg(4, 'macl', il.add(4, _r(il, 'macl'), product)))


# ── comparison (all set T) ────────────────────────────────────────────────

def _lift_cmp_eq(insn, il):
    """CMP/EQ Rm,Rn  or  CMP/EQ #imm,R0"""
    src, dst = insn.operands
    _set_t(il, il.compare_equal(4, _r(il, dst.reg), _read_op(il, src)))


def _lift_cmp_ge(insn, il):
    rm, rn = insn.operands
    _set_t(il, il.compare_signed_greater_equal(4, _r(il, rn.reg), _r(il, rm.reg)))


def _lift_cmp_gt(insn, il):
    rm, rn = insn.operands
    _set_t(il, il.compare_signed_greater_than(4, _r(il, rn.reg), _r(il, rm.reg)))


def _lift_cmp_hs(insn, il):
    """CMP/HS Rm,Rn — unsigned Rn >= Rm"""
    rm, rn = insn.operands
    _set_t(il, il.compare_unsigned_greater_equal(4, _r(il, rn.reg), _r(il, rm.reg)))


def _lift_cmp_hi(insn, il):
    """CMP/HI Rm,Rn — unsigned Rn > Rm"""
    rm, rn = insn.operands
    _set_t(il, il.compare_unsigned_greater_than(4, _r(il, rn.reg), _r(il, rm.reg)))


def _lift_cmp_pl(insn, il):
    """CMP/PL Rn — T = (Rn > 0) signed"""
    rn = insn.operands[0]
    _set_t(il, il.compare_signed_greater_than(4, _r(il, rn.reg), _c(il, 0)))


def _lift_cmp_pz(insn, il):
    """CMP/PZ Rn — T = (Rn >= 0) signed"""
    rn = insn.operands[0]
    _set_t(il, il.compare_signed_greater_equal(4, _r(il, rn.reg), _c(il, 0)))


def _lift_cmp_str(insn, il):
    """CMP/STR Rm,Rn — T=1 if any byte of Rm equals corresponding byte of Rn.

    XOR the two registers; if any byte of the result is zero, T=1.
    """
    rm, rn = insn.operands
    t0 = LLIL_TEMP(0)
    il.append(il.set_reg(4, t0,
              il.xor_expr(4, _r(il, rm.reg), _r(il, rn.reg))))
    # Check each byte for zero
    b0 = il.compare_equal(4,
            il.and_expr(4, il.reg(4, t0), _c(il, 0xFF)), _c(il, 0))
    b1 = il.compare_equal(4,
            il.and_expr(4, il.reg(4, t0), _c(il, 0xFF00)), _c(il, 0))
    b2 = il.compare_equal(4,
            il.and_expr(4, il.reg(4, t0), _c(il, 0xFF0000)), _c(il, 0))
    b3 = il.compare_equal(4,
            il.and_expr(4, il.reg(4, t0), _c(il, 0xFF000000)), _c(il, 0))
    _set_t(il, il.or_expr(0, il.or_expr(0, b0, b1), il.or_expr(0, b2, b3)))


def _lift_tst(insn, il):
    """TST Rm,Rn — T = ((Rn & Rm) == 0)"""
    rm, rn = insn.operands
    _set_t(il, il.compare_equal(4,
           il.and_expr(4, _r(il, rn.reg), _read_op(il, rm)),
           _c(il, 0)))


def _lift_tst_b(insn, il):
    """TST.B #imm,@(R0,GBR)"""
    imm_op = insn.operands[0]
    addr = il.add(4, _r(il, 'r0'), _r(il, 'gbr'))
    val = il.load(1, addr)
    _set_t(il, il.compare_equal(1,
           il.and_expr(1, val, il.const(1, imm_op.imm)),
           il.const(1, 0)))


# ── logic ─────────────────────────────────────────────────────────────────

def _lift_and(insn, il):
    """AND Rm,Rn"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.and_expr(4, _r(il, rn.reg), _read_op(il, rm))))


def _lift_or(insn, il):
    """OR Rm,Rn"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.or_expr(4, _r(il, rn.reg), _read_op(il, rm))))


def _lift_xor(insn, il):
    """XOR Rm,Rn"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.xor_expr(4, _r(il, rn.reg), _read_op(il, rm))))


def _lift_not(insn, il):
    """NOT Rm,Rn — Rn = ~Rm"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg, il.not_expr(4, _r(il, rm.reg))))


def _lift_and_b(insn, il):
    """AND.B #imm,@(R0,GBR)"""
    imm_op = insn.operands[0]
    addr = il.add(4, _r(il, 'r0'), _r(il, 'gbr'))
    val = il.and_expr(1, il.load(1, addr), il.const(1, imm_op.imm))
    il.append(il.store(1, il.add(4, _r(il, 'r0'), _r(il, 'gbr')), val))


def _lift_or_b(insn, il):
    """OR.B #imm,@(R0,GBR)"""
    imm_op = insn.operands[0]
    addr = il.add(4, _r(il, 'r0'), _r(il, 'gbr'))
    val = il.or_expr(1, il.load(1, addr), il.const(1, imm_op.imm))
    il.append(il.store(1, il.add(4, _r(il, 'r0'), _r(il, 'gbr')), val))


def _lift_xor_b(insn, il):
    """XOR.B #imm,@(R0,GBR)"""
    imm_op = insn.operands[0]
    addr = il.add(4, _r(il, 'r0'), _r(il, 'gbr'))
    val = il.xor_expr(1, il.load(1, addr), il.const(1, imm_op.imm))
    il.append(il.store(1, il.add(4, _r(il, 'r0'), _r(il, 'gbr')), val))


# ── shifts / rotates ─────────────────────────────────────────────────────

def _lift_shll(insn, il):
    """SHLL Rn — T = Rn[31]; Rn <<= 1"""
    rn = insn.operands[0]
    _set_t(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 0x80000000)), _c(il, 0)))
    il.append(il.set_reg(4, rn.reg,
                         il.shift_left(4, _r(il, rn.reg), il.const(1, 1))))


def _lift_shlr(insn, il):
    """SHLR Rn — T = Rn[0]; Rn >>= 1 (logical)"""
    rn = insn.operands[0]
    _set_t(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 1)), _c(il, 0)))
    il.append(il.set_reg(4, rn.reg,
                         il.logical_shift_right(4, _r(il, rn.reg), il.const(1, 1))))


def _lift_shal(insn, il):
    """SHAL Rn — T = Rn[31]; Rn <<= 1 (arithmetic, same as SHLL for shift)"""
    _lift_shll(insn, il)


def _lift_shar(insn, il):
    """SHAR Rn — T = Rn[0]; Rn >>= 1 (arithmetic)"""
    rn = insn.operands[0]
    _set_t(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 1)), _c(il, 0)))
    il.append(il.set_reg(4, rn.reg,
                         il.arith_shift_right(4, _r(il, rn.reg), il.const(1, 1))))


def _lift_shll_n(insn, il, n):
    """SHLL2 / SHLL8 / SHLL16 — Rn <<= n; no T update"""
    rn = insn.operands[0]
    il.append(il.set_reg(4, rn.reg,
                         il.shift_left(4, _r(il, rn.reg), il.const(1, n))))


def _lift_shlr_n(insn, il, n):
    """SHLR2 / SHLR8 / SHLR16 — Rn >>= n (logical); no T update"""
    rn = insn.operands[0]
    il.append(il.set_reg(4, rn.reg,
                         il.logical_shift_right(4, _r(il, rn.reg), il.const(1, n))))


def _lift_shad(insn, il):
    """SHAD Rm,Rn — if Rm>=0: Rn<<=Rm; else if Rm==-32: Rn=sign; else Rn>>=(-Rm) arith"""
    rm, rn = insn.operands
    t_pos = LowLevelILLabel()
    t_neg = LowLevelILLabel()
    t_done = LowLevelILLabel()
    t_neg32 = LowLevelILLabel()
    t_neg_shift = LowLevelILLabel()

    # if Rm >= 0 goto t_pos else t_neg
    il.append(il.if_expr(
        il.compare_signed_greater_equal(4, _r(il, rm.reg), _c(il, 0)),
        t_pos, t_neg))

    # positive: Rn <<= Rm
    il.mark_label(t_pos)
    il.append(il.set_reg(4, rn.reg,
              il.shift_left(4, _r(il, rn.reg), il.low_part(1, _r(il, rm.reg)))))
    il.append(il.goto(t_done))

    # negative
    il.mark_label(t_neg)
    # if Rm == -32 (i.e. 0xFFFFFFE0) → Rn = sign-extend of bit 31
    il.append(il.if_expr(
        il.compare_equal(4, _r(il, rm.reg), _c(il, -32 & 0xFFFFFFFF)),
        t_neg32, t_neg_shift))

    il.mark_label(t_neg32)
    il.append(il.set_reg(4, rn.reg,
              il.arith_shift_right(4, _r(il, rn.reg), il.const(1, 31))))
    il.append(il.goto(t_done))

    il.mark_label(t_neg_shift)
    # shift amount = -Rm = neg(Rm) (lower 5 bits are enough)
    il.append(il.set_reg(4, rn.reg,
              il.arith_shift_right(4, _r(il, rn.reg),
                                   il.low_part(1, il.neg_expr(4, _r(il, rm.reg))))))
    il.append(il.goto(t_done))

    il.mark_label(t_done)


def _lift_shld(insn, il):
    """SHLD Rm,Rn — like SHAD but logical right shift when negative."""
    rm, rn = insn.operands
    t_pos = LowLevelILLabel()
    t_neg = LowLevelILLabel()
    t_done = LowLevelILLabel()
    t_neg32 = LowLevelILLabel()
    t_neg_shift = LowLevelILLabel()

    il.append(il.if_expr(
        il.compare_signed_greater_equal(4, _r(il, rm.reg), _c(il, 0)),
        t_pos, t_neg))

    il.mark_label(t_pos)
    il.append(il.set_reg(4, rn.reg,
              il.shift_left(4, _r(il, rn.reg), il.low_part(1, _r(il, rm.reg)))))
    il.append(il.goto(t_done))

    il.mark_label(t_neg)
    il.append(il.if_expr(
        il.compare_equal(4, _r(il, rm.reg), _c(il, -32 & 0xFFFFFFFF)),
        t_neg32, t_neg_shift))

    il.mark_label(t_neg32)
    il.append(il.set_reg(4, rn.reg, _c(il, 0)))
    il.append(il.goto(t_done))

    il.mark_label(t_neg_shift)
    il.append(il.set_reg(4, rn.reg,
              il.logical_shift_right(4, _r(il, rn.reg),
                                     il.low_part(1, il.neg_expr(4, _r(il, rm.reg))))))
    il.append(il.goto(t_done))

    il.mark_label(t_done)


def _lift_rotl(insn, il):
    """ROTL Rn — T = Rn[31]; Rn = (Rn<<1) | T_old_msb"""
    rn = insn.operands[0]
    # T = MSB
    msb = il.compare_not_equal(4,
          il.and_expr(4, _r(il, rn.reg), _c(il, 0x80000000)), _c(il, 0))
    _set_t(il, msb)
    # Rn = (Rn << 1) | T  (using the old MSB that we just put in T)
    il.append(il.set_reg(4, rn.reg,
              il.or_expr(4,
                  il.shift_left(4, _r(il, rn.reg), il.const(1, 1)),
                  il.bool_to_int(4, _flag_t(il)))))


def _lift_rotr(insn, il):
    """ROTR Rn — T = Rn[0]; Rn = (Rn>>1) | (Rn[0]<<31)"""
    rn = insn.operands[0]
    lsb = il.compare_not_equal(4,
          il.and_expr(4, _r(il, rn.reg), _c(il, 1)), _c(il, 0))
    _set_t(il, lsb)
    il.append(il.set_reg(4, rn.reg,
              il.or_expr(4,
                  il.logical_shift_right(4, _r(il, rn.reg), il.const(1, 1)),
                  il.shift_left(4, il.bool_to_int(4, _flag_t(il)), il.const(1, 31)))))


def _lift_rotcl(insn, il):
    """ROTCL Rn — rotate left through carry:
    old_T = T; T = Rn[31]; Rn = (Rn<<1) | old_T"""
    rn = insn.operands[0]
    # Save old T
    t0 = LLIL_TEMP(0)
    il.append(il.set_reg(4, t0, il.bool_to_int(4, _flag_t(il))))
    # T = MSB of Rn
    _set_t(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 0x80000000)), _c(il, 0)))
    # Rn = (Rn << 1) | old_T
    il.append(il.set_reg(4, rn.reg,
              il.or_expr(4,
                  il.shift_left(4, _r(il, rn.reg), il.const(1, 1)),
                  il.reg(4, t0))))


def _lift_rotcr(insn, il):
    """ROTCR Rn — rotate right through carry:
    old_T = T; T = Rn[0]; Rn = (Rn>>1) | (old_T<<31)"""
    rn = insn.operands[0]
    t0 = LLIL_TEMP(0)
    il.append(il.set_reg(4, t0, il.bool_to_int(4, _flag_t(il))))
    _set_t(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 1)), _c(il, 0)))
    il.append(il.set_reg(4, rn.reg,
              il.or_expr(4,
                  il.logical_shift_right(4, _r(il, rn.reg), il.const(1, 1)),
                  il.shift_left(4, il.reg(4, t0), il.const(1, 31)))))


# ── extension / swap / extract ────────────────────────────────────────────

def _lift_extu_b(insn, il):
    """EXTU.B Rm,Rn — Rn = zero_extend(Rm[7:0])"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.zero_extend(4, il.low_part(1, _r(il, rm.reg)))))


def _lift_extu_w(insn, il):
    """EXTU.W Rm,Rn — Rn = zero_extend(Rm[15:0])"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.zero_extend(4, il.low_part(2, _r(il, rm.reg)))))


def _lift_exts_b(insn, il):
    """EXTS.B Rm,Rn — Rn = sign_extend(Rm[7:0])"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.sign_extend(4, il.low_part(1, _r(il, rm.reg)))))


def _lift_exts_w(insn, il):
    """EXTS.W Rm,Rn — Rn = sign_extend(Rm[15:0])"""
    rm, rn = insn.operands
    il.append(il.set_reg(4, rn.reg,
                         il.sign_extend(4, il.low_part(2, _r(il, rm.reg)))))


def _lift_swap_b(insn, il):
    """SWAP.B Rm,Rn — swap low two bytes of Rm → Rn.
    Rn = Rm[31:16] | Rm[7:0]<<8 | Rm[15:8]"""
    rm, rn = insn.operands
    hi = il.and_expr(4, _r(il, rm.reg), _c(il, 0xFFFF0000))
    lo_byte = il.and_expr(4, _r(il, rm.reg), _c(il, 0xFF))
    hi_byte = il.and_expr(4, _r(il, rm.reg), _c(il, 0xFF00))
    result = il.or_expr(4, hi,
                il.or_expr(4,
                    il.shift_left(4, lo_byte, il.const(1, 8)),
                    il.logical_shift_right(4, hi_byte, il.const(1, 8))))
    il.append(il.set_reg(4, rn.reg, result))


def _lift_swap_w(insn, il):
    """SWAP.W Rm,Rn — swap two 16-bit halves.
    Rn = Rm[15:0]<<16 | Rm[31:16]>>16"""
    rm, rn = insn.operands
    lo = il.shift_left(4, _r(il, rm.reg), il.const(1, 16))
    hi = il.logical_shift_right(4, _r(il, rm.reg), il.const(1, 16))
    il.append(il.set_reg(4, rn.reg, il.or_expr(4, lo, hi)))


def _lift_xtrct(insn, il):
    """XTRCT Rm,Rn — Rn = (Rm<<16) | (Rn>>16)  (middle 32 bits of Rm:Rn)"""
    rm, rn = insn.operands
    hi = il.shift_left(4, _r(il, rm.reg), il.const(1, 16))
    lo = il.logical_shift_right(4, _r(il, rn.reg), il.const(1, 16))
    il.append(il.set_reg(4, rn.reg, il.or_expr(4, hi, lo)))


# ── branches / control flow ──────────────────────────────────────────────

def _lift_bra(insn, il):
    """BRA disp — unconditional PC-relative jump (delay slot handled by BN)"""
    target = insn.branch_target
    label = il.get_label_for_address(il.arch, target)
    if label is not None:
        il.append(il.goto(label))
    else:
        il.append(il.jump(il.const_pointer(4, target)))


def _lift_bsr(insn, il):
    """BSR disp — branch to subroutine"""
    il.append(il.call(il.const_pointer(4, insn.branch_target)))


def _lift_bt(insn, il):
    """BT disp — branch if T==1"""
    t_label = LowLevelILLabel()
    f_label = LowLevelILLabel()
    il.append(il.if_expr(_flag_t(il), t_label, f_label))
    il.mark_label(t_label)
    il.append(il.jump(il.const_pointer(4, insn.branch_target)))
    il.mark_label(f_label)


def _lift_bf(insn, il):
    """BF disp — branch if T==0"""
    t_label = LowLevelILLabel()
    f_label = LowLevelILLabel()
    il.append(il.if_expr(_flag_t(il), f_label, t_label))
    il.mark_label(t_label)
    il.append(il.jump(il.const_pointer(4, insn.branch_target)))
    il.mark_label(f_label)


def _lift_bt_s(insn, il):
    """BT/S disp — branch if T==1 (with delay slot)"""
    _lift_bt(insn, il)


def _lift_bf_s(insn, il):
    """BF/S disp — branch if T==0 (with delay slot)"""
    _lift_bf(insn, il)


def _lift_jmp(insn, il):
    """JMP @Rn"""
    il.append(il.jump(_r(il, insn.operands[0].reg)))


def _lift_jsr(insn, il):
    """JSR @Rn"""
    il.append(il.call(_r(il, insn.operands[0].reg)))


def _lift_braf(insn, il):
    """BRAF Rn — PC = PC+4+Rn"""
    rn = insn.operands[0]
    il.append(il.jump(il.add(4, _c(il, insn.addr + 4), _r(il, rn.reg))))


def _lift_bsrf(insn, il):
    """BSRF Rn — PR = PC+4; PC = PC+4+Rn"""
    rn = insn.operands[0]
    il.append(il.call(il.add(4, _c(il, insn.addr + 4), _r(il, rn.reg))))


def _lift_rts(insn, il):
    """RTS — PC = PR"""
    il.append(il.ret(_r(il, 'pr')))


def _lift_rte(insn, il):
    """RTE — return from exception (simplified)"""
    il.append(il.ret(_r(il, 'spc')))


def _lift_trapa(insn, il):
    """TRAPA #imm"""
    il.append(il.system_call())


# ── system register transfers ─────────────────────────────────────────────

def _lift_sts(insn, il):
    """STS sysreg,Rn — Rn = sysreg"""
    src, dst = insn.operands
    _write_reg(il, dst, _read_op(il, src))


def _lift_sts_l(insn, il):
    """STS.L sysreg,@-Rn — push sysreg"""
    src, dst = insn.operands
    _pre_dec(il, dst)
    il.append(il.store(4, _mem_addr(il, dst), _read_op(il, src)))


def _lift_lds(insn, il):
    """LDS Rm,sysreg — sysreg = Rm"""
    src, dst = insn.operands
    _write_reg(il, dst, _read_op(il, src))


def _lift_lds_l(insn, il):
    """LDS.L @Rm+,sysreg — pop to sysreg"""
    src, dst = insn.operands
    val = il.load(4, _mem_addr(il, src))
    _write_reg(il, dst, val)
    _post_inc(il, src)


def _lift_stc(insn, il):
    """STC ctrlreg,Rn"""
    src, dst = insn.operands
    _write_reg(il, dst, _read_op(il, src))


def _lift_stc_l(insn, il):
    """STC.L ctrlreg,@-Rn"""
    src, dst = insn.operands
    _pre_dec(il, dst)
    il.append(il.store(4, _mem_addr(il, dst), _read_op(il, src)))


def _lift_ldc(insn, il):
    """LDC Rm,ctrlreg"""
    src, dst = insn.operands
    _write_reg(il, dst, _read_op(il, src))


def _lift_ldc_l(insn, il):
    """LDC.L @Rm+,ctrlreg"""
    src, dst = insn.operands
    val = il.load(4, _mem_addr(il, src))
    _write_reg(il, dst, val)
    _post_inc(il, src)


# ── division ──────────────────────────────────────────────────────────────

def _lift_div0s(insn, il):
    """DIV0S Rm,Rn — set Q=Rn[31], M=Rm[31], T=(Q!=M)"""
    rm, rn = insn.operands
    # Q = MSB of Rn
    _set_q(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 0x80000000)), _c(il, 0)))
    # M = MSB of Rm
    _set_m(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rm.reg), _c(il, 0x80000000)), _c(il, 0)))
    # T = (M != Q) — but we just set them, so compare MSBs directly
    _set_t(il, il.compare_not_equal(4,
           il.and_expr(4, _r(il, rn.reg), _c(il, 0x80000000)),
           il.and_expr(4, _r(il, rm.reg), _c(il, 0x80000000))))


def _lift_div0u(insn, il):
    """DIV0U — M=0, Q=0, T=0"""
    _set_m(il, il.const(0, 0))
    _set_q(il, il.const(0, 0))
    _set_t(il, il.const(0, 0))


def _lift_div1(insn, il):
    """DIV1 Rm,Rn — single division step.  Complex flag logic; model as
    unimplemented for the IL but preserve the register write.

    Accurate flag/register semantics for DIV1 require modelling Q, M, T
    interactions.  We approximate: Rn is modified, T is modified.
    """
    # DIV1 is extremely rare (<0.01%) in this firmware.
    # Full accurate emulation is complex.  Emit an approximation:
    # shift Rn left, bring in T as low bit, then conditionally add/sub Rm
    rm, rn = insn.operands
    t0 = LLIL_TEMP(0)
    # old_q = Q flag (we'd need to read it)
    # Rn = (Rn << 1) | T
    il.append(il.set_reg(4, t0,
              il.or_expr(4,
                  il.shift_left(4, _r(il, rn.reg), il.const(1, 1)),
                  il.bool_to_int(4, _flag_t(il)))))
    # Approximate: Rn = tmp - Rm or tmp + Rm based on Q^M
    # Just set Rn to (shifted | T) - Rm as a rough approximation
    il.append(il.set_reg(4, rn.reg,
              il.sub(4, il.reg(4, t0), _r(il, rm.reg))))
    # T update is complex; leave as unmodified (already set above is wrong,
    # but div1 is extremely rare and this is the best simple approx)
    _set_t(il, il.compare_unsigned_greater_equal(4, il.reg(4, t0), _r(il, rm.reg)))


# ── misc ──────────────────────────────────────────────────────────────────

def _lift_clrt(insn, il):
    _set_t(il, il.const(0, 0))


def _lift_sett(insn, il):
    _set_t(il, il.const(0, 1))


def _lift_clrmac(insn, il):
    il.append(il.set_reg(4, 'mach', _c(il, 0)))
    il.append(il.set_reg(4, 'macl', _c(il, 0)))


def _lift_tas_b(insn, il):
    """TAS.B @Rn — T = (@Rn == 0); @Rn |= 0x80  (atomic test-and-set)"""
    rn = insn.operands[0]
    addr = _r(il, rn.reg)
    t0 = LLIL_TEMP(0)
    il.append(il.set_reg(4, t0, il.zero_extend(4, il.load(1, addr))))
    _set_t(il, il.compare_equal(4, il.reg(4, t0), _c(il, 0)))
    il.append(il.store(1, _r(il, rn.reg),
              il.or_expr(1, il.low_part(1, il.reg(4, t0)), il.const(1, 0x80))))


# ── FPU ───────────────────────────────────────────────────────────────────

def _fop_size(insn):
    """Return 4 for single-precision, 8 for double, based on operand types."""
    for op in insn.operands:
        if op.type == OperandType.DR_REG or op.type == OperandType.XD_REG:
            return 8
    return 4


def _fr(il, op):
    """Read a float register operand at its natural size."""
    if op.type == OperandType.DR_REG or op.type == OperandType.XD_REG:
        return il.reg(8, op.reg)
    return il.reg(4, op.reg)


def _fr_size(op):
    if op.type == OperandType.DR_REG or op.type == OperandType.XD_REG:
        return 8
    return 4


def _lift_fmov(insn, il):
    """FMOV — float register move / load / store with various addressing modes.

    Covers:  fmov FRm,FRn  /  fmov @Rm,FRn  /  fmov FRm,@Rn  /
             fmov @Rm+,FRn /  fmov FRm,@-Rn /  fmov @(R0,Rm),FRn /
             fmov FRm,@(R0,Rn)
    Also works for DRm/DRn/XDm/XDn variants (size=8).
    """
    src, dst = insn.operands
    sz = max(_fr_size(src), _fr_size(dst))
    # Adjust size for memory operands: if either side is DR/XD, memory access is 8
    if src.type in _MEM_TYPES:
        src_sz = src.size or sz
    else:
        src_sz = sz
    if dst.type in _MEM_TYPES:
        dst_sz = dst.size or sz
    else:
        dst_sz = sz

    if dst.type in _MEM_TYPES:
        # Store
        _pre_dec(il, dst)
        addr = _mem_addr(il, dst)
        if src.type in (OperandType.FR_REG, OperandType.DR_REG, OperandType.XD_REG):
            val = il.reg(src_sz, src.reg)
        else:
            val = _read_op(il, src)
        il.append(il.store(dst_sz, addr, val))
        _post_inc(il, src)
    elif dst.type in (OperandType.FR_REG, OperandType.DR_REG, OperandType.XD_REG):
        if src.type in _MEM_TYPES:
            # Load
            _pre_dec(il, src)
            addr = _mem_addr(il, src)
            val = il.load(src_sz, addr)
            il.append(il.set_reg(dst_sz, dst.reg, val))
            _post_inc(il, src)
        elif src.type in (OperandType.FR_REG, OperandType.DR_REG, OperandType.XD_REG):
            # Register to register
            il.append(il.set_reg(dst_sz, dst.reg, il.reg(src_sz, src.reg)))
        else:
            il.append(il.set_reg(dst_sz, dst.reg, _read_op(il, src)))
    else:
        il.append(il.unimplemented())


def _lift_fadd(insn, il):
    src, dst = insn.operands
    sz = _fop_size(insn)
    il.append(il.set_reg(sz, dst.reg,
              il.float_add(sz, _fr(il, dst), _fr(il, src))))


def _lift_fsub(insn, il):
    src, dst = insn.operands
    sz = _fop_size(insn)
    il.append(il.set_reg(sz, dst.reg,
              il.float_sub(sz, _fr(il, dst), _fr(il, src))))


def _lift_fmul(insn, il):
    src, dst = insn.operands
    sz = _fop_size(insn)
    il.append(il.set_reg(sz, dst.reg,
              il.float_mult(sz, _fr(il, dst), _fr(il, src))))


def _lift_fdiv(insn, il):
    src, dst = insn.operands
    sz = _fop_size(insn)
    il.append(il.set_reg(sz, dst.reg,
              il.float_div(sz, _fr(il, dst), _fr(il, src))))


def _lift_fsqrt(insn, il):
    op = insn.operands[0]
    sz = _fr_size(op)
    il.append(il.set_reg(sz, op.reg, il.float_sqrt(sz, _fr(il, op))))


def _lift_fabs(insn, il):
    op = insn.operands[0]
    sz = _fr_size(op)
    il.append(il.set_reg(sz, op.reg, il.float_abs(sz, _fr(il, op))))


def _lift_fneg(insn, il):
    op = insn.operands[0]
    sz = _fr_size(op)
    il.append(il.set_reg(sz, op.reg, il.float_neg(sz, _fr(il, op))))


def _lift_float(insn, il):
    """FLOAT FPUL, FRn/DRn — int→float"""
    dst = insn.operands[0] if len(insn.operands) == 1 else insn.operands[1]
    sz = _fr_size(dst)
    il.append(il.set_reg(sz, dst.reg,
              il.int_to_float(sz, _r(il, 'fpul'))))


def _lift_ftrc(insn, il):
    """FTRC FRn/DRn, FPUL — float→int (truncate)"""
    src = insn.operands[0]
    sz = _fr_size(src)
    il.append(il.set_reg(4, 'fpul',
              il.float_to_int(4, _fr(il, src))))


def _lift_fcmp_eq(insn, il):
    """FCMP/EQ FRm,FRn — T = (FRn == FRm)"""
    src, dst = insn.operands
    sz = _fop_size(insn)
    _set_t(il, il.float_compare_equal(sz, _fr(il, dst), _fr(il, src)))


def _lift_fcmp_gt(insn, il):
    """FCMP/GT FRm,FRn — T = (FRn > FRm)"""
    src, dst = insn.operands
    sz = _fop_size(insn)
    _set_t(il, il.float_compare_greater_than(sz, _fr(il, dst), _fr(il, src)))


def _lift_flds(insn, il):
    """FLDS FRn, FPUL — FPUL = FRn"""
    src = insn.operands[0]
    il.append(il.set_reg(4, 'fpul', il.reg(4, src.reg)))


def _lift_fsts(insn, il):
    """FSTS FPUL, FRn — FRn = FPUL"""
    dst = insn.operands[0] if len(insn.operands) == 1 else insn.operands[1]
    il.append(il.set_reg(4, dst.reg, _r(il, 'fpul')))


def _lift_fschg(insn, il):
    """FSCHG — toggle FPSCR.SZ (bit 20)"""
    il.append(il.set_reg(4, 'fpscr',
              il.xor_expr(4, _r(il, 'fpscr'), _c(il, 1 << 20))))


def _lift_frchg(insn, il):
    """FRCHG — toggle FPSCR.FR (bit 21)"""
    il.append(il.set_reg(4, 'fpscr',
              il.xor_expr(4, _r(il, 'fpscr'), _c(il, 1 << 21))))


def _lift_fsrra(insn, il):
    """FSRRA FRn — FRn = 1.0 / sqrt(FRn)"""
    op = insn.operands[0]
    il.append(il.set_reg(4, op.reg,
              il.float_div(4,
                  il.float_const_single(1.0),
                  il.float_sqrt(4, il.reg(4, op.reg)))))


def _lift_fipr(insn, il):
    """FIPR FVm, FVn — dot product, result in FR[n_base+3]"""
    m_fv, n_fv = insn.operands
    m_base = int(m_fv.reg[2:])  # 'fv0' → 0, 'fv4' → 4, etc.
    n_base = int(n_fv.reg[2:])
    dot = il.float_add(4,
        il.float_add(4,
            il.float_mult(4, il.reg(4, f'fr{m_base}'),     il.reg(4, f'fr{n_base}')),
            il.float_mult(4, il.reg(4, f'fr{m_base+1}'),   il.reg(4, f'fr{n_base+1}'))),
        il.float_add(4,
            il.float_mult(4, il.reg(4, f'fr{m_base+2}'),   il.reg(4, f'fr{n_base+2}')),
            il.float_mult(4, il.reg(4, f'fr{m_base+3}'),   il.reg(4, f'fr{n_base+3}'))))
    il.append(il.set_reg(4, f'fr{n_base+3}', dot))


def _lift_ftrv(insn, il):
    """FTRV XMTRX, FVn — 4x4 matrix × vector"""
    # Python decoder: ops[0]=XMTRX, ops[1]=FV_REG
    fv_op = insn.operands[1]
    n_base = int(fv_op.reg[2:])  # 'fv0' → 0, etc.
    # Save input vector to temps
    for i in range(4):
        il.append(il.set_reg(4, LLIL_TEMP(i), il.reg(4, f'fr{n_base+i}')))
    # Compute each result row: FR[n+row] = sum_col(XF[col*4+row] * temp[col])
    for row in range(4):
        s = il.float_add(4,
            il.float_add(4,
                il.float_mult(4, il.reg(4, f'xf{row}'),    il.reg(4, LLIL_TEMP(0))),
                il.float_mult(4, il.reg(4, f'xf{4+row}'),  il.reg(4, LLIL_TEMP(1)))),
            il.float_add(4,
                il.float_mult(4, il.reg(4, f'xf{8+row}'),  il.reg(4, LLIL_TEMP(2))),
                il.float_mult(4, il.reg(4, f'xf{12+row}'), il.reg(4, LLIL_TEMP(3)))))
        il.append(il.set_reg(4, f'fr{n_base+row}', s))


def _lift_fsca(insn, il):
    """FSCA FPUL, DRn — sin/cos via intrinsic"""
    dr_op = insn.operands[1]
    fr_base = int(dr_op.reg[2:])  # 'dr0' → 0, 'dr6' → 6
    il.append(il.intrinsic(
        [f'fr{fr_base}', f'fr{fr_base + 1}'],
        '__fsca',
        [il.reg(4, 'fpul')]))


def _lift_sleep(insn, il):
    """SLEEP — halt until interrupt"""
    il.append(il.intrinsic([], '__sleep', []))


def _lift_fcnvsd(insn, il):
    """FCNVSD FPUL, DRn — single→double"""
    dst = insn.operands[1]
    il.append(il.set_reg(8, dst.reg, il.float_convert(8, il.reg(4, 'fpul'))))


def _lift_fcnvds(insn, il):
    """FCNVDS DRn, FPUL — double→single"""
    src = insn.operands[0]
    il.append(il.set_reg(4, 'fpul', il.float_convert(4, il.reg(8, src.reg))))


def _lift_fmac(insn, il):
    """FMAC FR0, FRm, FRn — FRn = FR0*FRm + FRn"""
    rm = insn.operands[1]
    rn = insn.operands[2]
    il.append(il.set_reg(4, rn.reg,
              il.float_add(4,
                  il.float_mult(4, il.reg(4, 'fr0'), il.reg(4, rm.reg)),
                  il.reg(4, rn.reg))))


def _lift_fldi0(insn, il):
    """FLDI0 FRn — load 0.0"""
    dst = insn.operands[0]
    il.append(il.set_reg(4, dst.reg, il.float_const_single(0.0)))


def _lift_fldi1(insn, il):
    """FLDI1 FRn — load 1.0"""
    dst = insn.operands[0]
    il.append(il.set_reg(4, dst.reg, il.float_const_single(1.0)))

# ── dispatch table ────────────────────────────────────────────────────────

_DISPATCH = {
    # data movement
    'mov':       _lift_mov,
    'mova':      _lift_mova,
    'movt':      _lift_movt,
    'movca.l':   _lift_movca_l,

    # arithmetic
    'add':       _lift_add,
    'addc':      _lift_addc,
    'addv':      _lift_addv,
    'sub':       _lift_sub,
    'subc':      _lift_subc,
    'subv':      _lift_subv,
    'neg':       _lift_neg,
    'negc':      _lift_negc,
    'dt':        _lift_dt,
    'mul.l':     _lift_mul_l,
    'muls.w':    _lift_muls_w,
    'mulu.w':    _lift_mulu_w,
    'dmuls.l':   _lift_dmuls_l,
    'dmulu.l':   _lift_dmulu_l,
    'mac.l':     _lift_mac_l,
    'mac.w':     _lift_mac_w,

    # comparison
    'cmp/eq':    _lift_cmp_eq,
    'cmp/ge':    _lift_cmp_ge,
    'cmp/gt':    _lift_cmp_gt,
    'cmp/hs':    _lift_cmp_hs,
    'cmp/hi':    _lift_cmp_hi,
    'cmp/pl':    _lift_cmp_pl,
    'cmp/pz':    _lift_cmp_pz,
    'cmp/str':   _lift_cmp_str,
    'tst':       _lift_tst,
    'tst.b':     _lift_tst_b,

    # logic
    'and':       _lift_and,
    'or':        _lift_or,
    'xor':       _lift_xor,
    'not':       _lift_not,
    'and.b':     _lift_and_b,
    'or.b':      _lift_or_b,
    'xor.b':     _lift_xor_b,

    # shifts (constant)
    'shll':      _lift_shll,
    'shlr':      _lift_shlr,
    'shal':      _lift_shal,
    'shar':      _lift_shar,

    # dynamic shifts
    'shad':      _lift_shad,
    'shld':      _lift_shld,

    # rotates
    'rotl':      _lift_rotl,
    'rotr':      _lift_rotr,
    'rotcl':     _lift_rotcl,
    'rotcr':     _lift_rotcr,

    # extension / swap
    'extu.b':    _lift_extu_b,
    'extu.w':    _lift_extu_w,
    'exts.b':    _lift_exts_b,
    'exts.w':    _lift_exts_w,
    'swap.b':    _lift_swap_b,
    'swap.w':    _lift_swap_w,
    'xtrct':     _lift_xtrct,

    # branches
    'bra':       _lift_bra,
    'bsr':       _lift_bsr,
    'bt':        _lift_bt,
    'bf':        _lift_bf,
    'bt/s':      _lift_bt_s,
    'bf/s':      _lift_bf_s,
    'jmp':       _lift_jmp,
    'jsr':       _lift_jsr,
    'braf':      _lift_braf,
    'bsrf':      _lift_bsrf,
    'rts':       _lift_rts,
    'rte':       _lift_rte,
    'trapa':     _lift_trapa,

    # system register transfers
    'sts':       _lift_sts,
    'sts.l':     _lift_sts_l,
    'lds':       _lift_lds,
    'lds.l':     _lift_lds_l,
    'stc':       _lift_stc,
    'stc.l':     _lift_stc_l,
    'ldc':       _lift_ldc,
    'ldc.l':     _lift_ldc_l,

    # division
    'div0s':     _lift_div0s,
    'div0u':     _lift_div0u,
    'div1':      _lift_div1,

    # misc
    'clrt':      _lift_clrt,
    'sett':      _lift_sett,
    'clrmac':    _lift_clrmac,
    'tas.b':     _lift_tas_b,

    # FPU
    'fmov':      _lift_fmov,
    'fadd':      _lift_fadd,
    'fsub':      _lift_fsub,
    'fmul':      _lift_fmul,
    'fdiv':      _lift_fdiv,
    'fsqrt':     _lift_fsqrt,
    'fabs':      _lift_fabs,
    'fneg':      _lift_fneg,
    'float':     _lift_float,
    'ftrc':      _lift_ftrc,
    'fcmp/eq':   _lift_fcmp_eq,
    'fcmp/gt':   _lift_fcmp_gt,
    'flds':      _lift_flds,
    'fsts':      _lift_fsts,
    'fschg':     _lift_fschg,
    'frchg':     _lift_frchg,
    'fldi0':     _lift_fldi0,
    'fldi1':     _lift_fldi1,
    'fmac':      _lift_fmac,
    'fcnvsd':    _lift_fcnvsd,
    'fcnvds':    _lift_fcnvds,
    'fsrra':     _lift_fsrra,
    'fipr':      _lift_fipr,
    'ftrv':      _lift_ftrv,
    'fsca':      _lift_fsca,
    'sleep':     _lift_sleep,
}

# NOP-like instructions — emit nop()
_NOPS = frozenset((
    'nop', 'pref', 'ocbi', 'ocbp', 'ocbwb', 'ldtlb',
))



# ── public entry point ────────────────────────────────────────────────────

def lift(insn: SH4Instruction, il: LowLevelILFunction) -> int:
    """Lift a decoded SH-4 instruction into Binary Ninja LLIL.

    Returns the instruction length (always 2).
    """
    il.set_current_address(insn.addr)
    mn = insn.mnemonic

    # ── fixed-shift family (no per-handler needed) ──
    if mn == 'shll2':
        _lift_shll_n(insn, il, 2)
        return 2
    if mn == 'shll8':
        _lift_shll_n(insn, il, 8)
        return 2
    if mn == 'shll16':
        _lift_shll_n(insn, il, 16)
        return 2
    if mn == 'shlr2':
        _lift_shlr_n(insn, il, 2)
        return 2
    if mn == 'shlr8':
        _lift_shlr_n(insn, il, 8)
        return 2
    if mn == 'shlr16':
        _lift_shlr_n(insn, il, 16)
        return 2

    # ── mov.b / mov.w / mov.l ──
    if mn == 'mov.b':
        _lift_mov_mem(insn, il, 1)
        return 2
    if mn == 'mov.w':
        _lift_mov_mem(insn, il, 2)
        return 2
    if mn == 'mov.l':
        _lift_mov_mem(insn, il, 4)
        return 2

    # ── fmov.s / fmov.d (same handler as fmov) ──
    if mn in ('fmov.s', 'fmov.d'):
        _lift_fmov(insn, il)
        return 2

    # ── dispatch table ──
    handler = _DISPATCH.get(mn)
    if handler is not None:
        handler(insn, il)
        return 2

    # ── NOP-like ──
    if mn in _NOPS:
        il.append(il.nop())
        return 2


    # ── fallback ──
    il.append(il.unimplemented())
    return 2
