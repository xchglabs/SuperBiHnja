/*  SuperBiHnja native SH-4 → Binary Ninja LLIL lifter.
 *
 *  Faithful port of superbiHnja/sh4_lift.py.
 *  Every handler from the Python lifter is reproduced here with identical
 *  IL semantics.
 */

#include "sh4_lift.h"

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using ExprId = BinaryNinja::ExprId;

/* ── tiny helpers ────────────────────────────────────────────────────── */

static ExprId R(LowLevelILFunction& il, uint32_t reg)
{
	return il.Register(4, reg);
}

static ExprId C(LowLevelILFunction& il, int64_t v)
{
	return il.Const(4, v);
}

static ExprId FlagT(LowLevelILFunction& il)
{
	return il.Flag(FLAG_T);
}

static void SetT(LowLevelILFunction& il, ExprId expr)
{
	il.AddInstruction(il.SetFlag(FLAG_T, expr));
}

static void SetQ(LowLevelILFunction& il, ExprId expr)
{
	il.AddInstruction(il.SetFlag(FLAG_Q, expr));
}

static void SetM(LowLevelILFunction& il, ExprId expr)
{
	il.AddInstruction(il.SetFlag(FLAG_M, expr));
}

/* Compute the effective address for a memory operand.
 * Pre-decrement / post-increment side-effects are NOT emitted here. */
static ExprId MemAddr(LowLevelILFunction& il, const SH4Operand& op)
{
	switch (op.type)
	{
	case OpType::AT_REG:
	case OpType::AT_REG_POST:
		return R(il, op.reg);
	case OpType::AT_PRE_REG:
		return R(il, op.reg); /* caller already emitted decrement */
	case OpType::DISP_REG:
		return il.Add(4, R(il, op.base), C(il, op.imm));
	case OpType::DISP_PC:
		return il.ConstPointer(4, (uint64_t)(uint32_t)op.imm);
	case OpType::DISP_GBR:
		return il.Add(4, R(il, REG_GBR), C(il, op.imm));
	case OpType::AT_R0_REG:
		return il.Add(4, R(il, REG_R0), R(il, op.base));
	case OpType::AT_R0_GBR:
		return il.Add(4, R(il, REG_R0), R(il, REG_GBR));
	default:
		return C(il, 0);
	}
}

/* Operand access size for memory operands. */
static size_t OpSize(const SH4Operand& op, size_t dflt = 4)
{
	/* For memory operands the size is encoded in the instruction via the
	 * mnemonic (mov.b=1, mov.w=2, mov.l=4).  The caller passes the size
	 * for load/store helpers; for other operands we use the default. */
	(void)op;
	return dflt;
}

static void PreDec(LowLevelILFunction& il, const SH4Operand& op, size_t sz)
{
	if (op.type == OpType::AT_PRE_REG)
		il.AddInstruction(il.SetRegister(4, op.reg, il.Sub(4, R(il, op.reg), C(il, (int64_t)sz))));
}

static void PostInc(LowLevelILFunction& il, const SH4Operand& op, size_t sz, uint32_t skipReg = REG_COUNT)
{
	if (op.type == OpType::AT_REG_POST)
	{
		if (skipReg != REG_COUNT && op.reg == skipReg)
			return;
		il.AddInstruction(il.SetRegister(4, op.reg, il.Add(4, R(il, op.reg), C(il, (int64_t)sz))));
	}
}

/* Read an operand value as a 4-byte IL expression.
 * Memory operands: loads op-size bytes; sign-extends bytes/words to 32-bit. */
static ExprId ReadOp(LowLevelILFunction& il, const SH4Operand& op, size_t memSz = 4)
{
	switch (op.type)
	{
	case OpType::REG:
	case OpType::CTRL_REG:
	case OpType::SYS_REG:
		return R(il, op.reg);
	case OpType::FR_REG:
	case OpType::XF_REG:
		return il.Register(4, op.reg);
	case OpType::DR_REG:
	case OpType::XD_REG:
		return il.Register(8, op.reg);
	case OpType::IMM:
		return C(il, op.imm);
	case OpType::ADDR:
		return il.ConstPointer(4, (uint64_t)(uint32_t)op.imm);
	default:
		break;
	}
	if (is_mem_type(op.type))
	{
		ExprId val = il.Load(memSz, MemAddr(il, op));
		if (memSz < 4)
			val = il.SignExtend(4, val);
		return val;
	}
	return il.Unimplemented();
}

/* Write *val* to a register operand. */
static void WriteReg(LowLevelILFunction& il, const SH4Operand& op, ExprId val)
{
	switch (op.type)
	{
	case OpType::REG:
	case OpType::CTRL_REG:
	case OpType::SYS_REG:
		il.AddInstruction(il.SetRegister(4, op.reg, val));
		break;
	case OpType::FR_REG:
	case OpType::XF_REG:
		il.AddInstruction(il.SetRegister(4, op.reg, val));
		break;
	case OpType::DR_REG:
	case OpType::XD_REG:
		il.AddInstruction(il.SetRegister(8, op.reg, val));
		break;
	default:
		break;
	}
}

/* FPU operand helpers */
static size_t FrSize(const SH4Operand& op)
{
	if (op.type == OpType::DR_REG || op.type == OpType::XD_REG)
		return 8;
	return 4;
}

static ExprId Fr(LowLevelILFunction& il, const SH4Operand& op)
{
	return il.Register(FrSize(op), op.reg);
}

static size_t FopSize(const SH4Instruction& insn)
{
	for (uint8_t i = 0; i < insn.op_count; i++)
	{
		if (insn.ops[i].type == OpType::DR_REG || insn.ops[i].type == OpType::XD_REG)
			return 8;
	}
	return 4;
}

/* ── data-movement ───────────────────────────────────────────────────── */

static void LiftMov(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, dst.reg, ReadOp(il, src)));
}

static void LiftMovMem(const SH4Instruction& insn, LowLevelILFunction& il, size_t size)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];

	if (is_mem_type(dst.type))
	{
		/* store */
		PreDec(il, dst, size);
		ExprId addr = MemAddr(il, dst);
		ExprId val = ReadOp(il, src);
		il.AddInstruction(il.Store(size, addr, val));
		PostInc(il, src, size);
	}
	else
	{
		/* load (to register) */
		PreDec(il, src, size);
		ExprId addr = MemAddr(il, src);
		ExprId val = il.Load(size, addr);
		if (size < 4)
			val = il.SignExtend(4, val);
		uint32_t dstReg = dst.reg;
		il.AddInstruction(il.SetRegister(4, dstReg, val));
		PostInc(il, src, size, dstReg);
	}
}

static void LiftMova(const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.AddInstruction(il.SetRegister(4, REG_R0, il.ConstPointer(4, (uint64_t)(uint32_t)insn.ops[0].imm)));
}

static void LiftMovt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.AddInstruction(il.SetRegister(4, insn.ops[0].reg, il.BoolToInt(4, FlagT(il))));
}

static void LiftMovcaL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.AddInstruction(il.Store(4, R(il, insn.ops[1].reg), R(il, REG_R0)));
}

/* ── arithmetic ──────────────────────────────────────────────────────── */

static void LiftAdd(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, dst.reg, il.Add(4, R(il, dst.reg), ReadOp(il, src))));
}

static void LiftAddc(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0), t1 = LLIL_TEMP(1);
	/* t0 = Rn + Rm */
	il.AddInstruction(il.SetRegister(4, t0, il.Add(4, R(il, rn.reg), R(il, rm.reg))));
	/* carry1 = (t0 < Rn) unsigned */
	ExprId carry1 = il.CompareUnsignedLessThan(4, il.Register(4, t0), R(il, rn.reg));
	/* t1 = t0 + T */
	il.AddInstruction(il.SetRegister(4, t1, il.Add(4, il.Register(4, t0), il.BoolToInt(4, FlagT(il)))));
	/* carry2 = (t1 < t0) */
	ExprId carry2 = il.CompareUnsignedLessThan(4, il.Register(4, t1), il.Register(4, t0));
	/* T = carry1 | carry2 */
	SetT(il, il.Or(0, carry1, carry2));
	/* Rn = t1 */
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Register(4, t1)));
}

static void LiftSub(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Sub(4, R(il, rn.reg), R(il, rm.reg))));
}

static void LiftSubc(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0), t1 = LLIL_TEMP(1);
	il.AddInstruction(il.SetRegister(4, t0, il.Sub(4, R(il, rn.reg), R(il, rm.reg))));
	ExprId borrow1 = il.CompareUnsignedLessThan(4, R(il, rn.reg), R(il, rm.reg));
	il.AddInstruction(il.SetRegister(4, t1, il.Sub(4, il.Register(4, t0), il.BoolToInt(4, FlagT(il)))));
	ExprId borrow2 = il.CompareUnsignedLessThan(4, il.Register(4, t0), il.BoolToInt(4, FlagT(il)));
	SetT(il, il.Or(0, borrow1, borrow2));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Register(4, t1)));
}

static void LiftAddv(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t old = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, old, R(il, rn.reg)));
	uint32_t result = LLIL_TEMP(1);
	il.AddInstruction(il.SetRegister(4, result, il.Add(4, R(il, rn.reg), R(il, rm.reg))));
	ExprId srcSign = il.Xor(4, il.Register(4, old), R(il, rm.reg));
	ExprId resSign = il.Xor(4, il.Register(4, result), il.Register(4, old));
	SetT(il, il.CompareNotEqual(4, il.And(4, il.And(4, il.Not(4, srcSign), resSign), C(il, 0x80000000)), C(il, 0)));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Register(4, result)));
}

static void LiftSubv(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t old = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, old, R(il, rn.reg)));
	uint32_t result = LLIL_TEMP(1);
	il.AddInstruction(il.SetRegister(4, result, il.Sub(4, R(il, rn.reg), R(il, rm.reg))));
	ExprId srcSign = il.Xor(4, il.Register(4, old), R(il, rm.reg));
	ExprId resSign = il.Xor(4, il.Register(4, result), il.Register(4, old));
	SetT(il, il.CompareNotEqual(4, il.And(4, il.And(4, srcSign, resSign), C(il, 0x80000000)), C(il, 0)));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Register(4, result)));
}

static void LiftNeg(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Neg(4, R(il, rm.reg))));
}

static void LiftNegc(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, t0, il.Neg(4, R(il, rm.reg))));
	ExprId borrow1 = il.CompareNotEqual(4, R(il, rm.reg), C(il, 0));
	uint32_t t1 = LLIL_TEMP(1);
	il.AddInstruction(il.SetRegister(4, t1, il.Sub(4, il.Register(4, t0), il.BoolToInt(4, FlagT(il)))));
	ExprId borrow2 = il.CompareUnsignedLessThan(4, il.Register(4, t0), il.BoolToInt(4, FlagT(il)));
	SetT(il, il.Or(0, borrow1, borrow2));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Register(4, t1)));
}

static void LiftDt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Sub(4, R(il, rn.reg), C(il, 1))));
	SetT(il, il.CompareEqual(4, R(il, rn.reg), C(il, 0)));
}

static void LiftMulL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, REG_MACL, il.Mult(4, R(il, rm.reg), R(il, rn.reg))));
}

static void LiftMulsW(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	ExprId a = il.SignExtend(4, il.LowPart(2, R(il, rm.reg)));
	ExprId b = il.SignExtend(4, il.LowPart(2, R(il, rn.reg)));
	il.AddInstruction(il.SetRegister(4, REG_MACL, il.Mult(4, a, b)));
}

static void LiftMuluW(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	ExprId a = il.ZeroExtend(4, il.LowPart(2, R(il, rm.reg)));
	ExprId b = il.ZeroExtend(4, il.LowPart(2, R(il, rn.reg)));
	il.AddInstruction(il.SetRegister(4, REG_MACL, il.Mult(4, a, b)));
}

static void LiftDmulsL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(
		il.SetRegisterSplit(4, REG_MACH, REG_MACL, il.MultDoublePrecSigned(4, R(il, rm.reg), R(il, rn.reg))));
}

static void LiftDmuluL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(
		il.SetRegisterSplit(4, REG_MACH, REG_MACL, il.MultDoublePrecUnsigned(4, R(il, rm.reg), R(il, rn.reg))));
}

static void LiftMacL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rmOp = insn.ops[0];
	const auto& rnOp = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0), t1 = LLIL_TEMP(1);
	il.AddInstruction(il.SetRegister(4, t0, il.Load(4, R(il, rmOp.reg))));
	il.AddInstruction(il.SetRegister(4, t1, il.Load(4, R(il, rnOp.reg))));
	il.AddInstruction(il.SetRegister(4, rmOp.reg, il.Add(4, R(il, rmOp.reg), C(il, 4))));
	il.AddInstruction(il.SetRegister(4, rnOp.reg, il.Add(4, R(il, rnOp.reg), C(il, 4))));
	ExprId product = il.Mult(4, il.Register(4, t0), il.Register(4, t1));
	il.AddInstruction(il.SetRegister(4, REG_MACL, il.Add(4, R(il, REG_MACL), product)));
}

static void LiftMacW(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rmOp = insn.ops[0];
	const auto& rnOp = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0), t1 = LLIL_TEMP(1);
	il.AddInstruction(il.SetRegister(4, t0, il.SignExtend(4, il.Load(2, R(il, rmOp.reg)))));
	il.AddInstruction(il.SetRegister(4, t1, il.SignExtend(4, il.Load(2, R(il, rnOp.reg)))));
	il.AddInstruction(il.SetRegister(4, rmOp.reg, il.Add(4, R(il, rmOp.reg), C(il, 2))));
	il.AddInstruction(il.SetRegister(4, rnOp.reg, il.Add(4, R(il, rnOp.reg), C(il, 2))));
	ExprId product = il.Mult(4, il.Register(4, t0), il.Register(4, t1));
	il.AddInstruction(il.SetRegister(4, REG_MACL, il.Add(4, R(il, REG_MACL), product)));
}

/* ── comparison (all set T) ──────────────────────────────────────────── */

static void LiftCmpEq(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	SetT(il, il.CompareEqual(4, R(il, dst.reg), ReadOp(il, src)));
}

static void LiftCmpGe(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	SetT(il, il.CompareSignedGreaterEqual(4, R(il, rn.reg), R(il, rm.reg)));
}

static void LiftCmpGt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	SetT(il, il.CompareSignedGreaterThan(4, R(il, rn.reg), R(il, rm.reg)));
}

static void LiftCmpHs(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	SetT(il, il.CompareUnsignedGreaterEqual(4, R(il, rn.reg), R(il, rm.reg)));
}

static void LiftCmpHi(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	SetT(il, il.CompareUnsignedGreaterThan(4, R(il, rn.reg), R(il, rm.reg)));
}

static void LiftCmpPl(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	SetT(il, il.CompareSignedGreaterThan(4, R(il, rn.reg), C(il, 0)));
}

static void LiftCmpPz(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	SetT(il, il.CompareSignedGreaterEqual(4, R(il, rn.reg), C(il, 0)));
}

static void LiftCmpStr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, t0, il.Xor(4, R(il, rm.reg), R(il, rn.reg))));
	ExprId b0 = il.CompareEqual(4, il.And(4, il.Register(4, t0), C(il, 0xFF)), C(il, 0));
	ExprId b1 = il.CompareEqual(4, il.And(4, il.Register(4, t0), C(il, 0xFF00)), C(il, 0));
	ExprId b2 = il.CompareEqual(4, il.And(4, il.Register(4, t0), C(il, 0xFF0000)), C(il, 0));
	ExprId b3 = il.CompareEqual(4, il.And(4, il.Register(4, t0), C(il, 0xFF000000)), C(il, 0));
	SetT(il, il.Or(0, il.Or(0, b0, b1), il.Or(0, b2, b3)));
}

static void LiftTst(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	SetT(il, il.CompareEqual(4, il.And(4, R(il, rn.reg), ReadOp(il, rm)), C(il, 0)));
}

static void LiftTstB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& immOp = insn.ops[0];
	ExprId addr = il.Add(4, R(il, REG_R0), R(il, REG_GBR));
	ExprId val = il.Load(1, addr);
	SetT(il, il.CompareEqual(1, il.And(1, val, il.Const(1, immOp.imm)), il.Const(1, 0)));
}

/* ── logic ───────────────────────────────────────────────────────────── */

static void LiftAnd(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.And(4, R(il, rn.reg), ReadOp(il, rm))));
}

static void LiftOr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Or(4, R(il, rn.reg), ReadOp(il, rm))));
}

static void LiftXor(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Xor(4, R(il, rn.reg), ReadOp(il, rm))));
}

static void LiftNot(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Not(4, R(il, rm.reg))));
}

static void LiftAndB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& immOp = insn.ops[0];
	ExprId addr = il.Add(4, R(il, REG_R0), R(il, REG_GBR));
	ExprId val = il.And(1, il.Load(1, addr), il.Const(1, immOp.imm));
	il.AddInstruction(il.Store(1, il.Add(4, R(il, REG_R0), R(il, REG_GBR)), val));
}

static void LiftOrB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& immOp = insn.ops[0];
	ExprId addr = il.Add(4, R(il, REG_R0), R(il, REG_GBR));
	ExprId val = il.Or(1, il.Load(1, addr), il.Const(1, immOp.imm));
	il.AddInstruction(il.Store(1, il.Add(4, R(il, REG_R0), R(il, REG_GBR)), val));
}

static void LiftXorB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& immOp = insn.ops[0];
	ExprId addr = il.Add(4, R(il, REG_R0), R(il, REG_GBR));
	ExprId val = il.Xor(1, il.Load(1, addr), il.Const(1, immOp.imm));
	il.AddInstruction(il.Store(1, il.Add(4, R(il, REG_R0), R(il, REG_GBR)), val));
}

/* ── shifts / rotates ────────────────────────────────────────────────── */

static void LiftShll(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	SetT(il, il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 0x80000000)), C(il, 0)));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ShiftLeft(4, R(il, rn.reg), il.Const(1, 1))));
}

static void LiftShlr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	SetT(il, il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 1)), C(il, 0)));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.LogicalShiftRight(4, R(il, rn.reg), il.Const(1, 1))));
}

static void LiftShar(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	SetT(il, il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 1)), C(il, 0)));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ArithShiftRight(4, R(il, rn.reg), il.Const(1, 1))));
}

static void LiftShllN(const SH4Instruction& insn, LowLevelILFunction& il, int n)
{
	const auto& rn = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ShiftLeft(4, R(il, rn.reg), il.Const(1, n))));
}

static void LiftShlrN(const SH4Instruction& insn, LowLevelILFunction& il, int n)
{
	const auto& rn = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.LogicalShiftRight(4, R(il, rn.reg), il.Const(1, n))));
}

static void LiftShad(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	LowLevelILLabel tPos, tNeg, tDone, tNeg32, tNegShift;

	il.AddInstruction(il.If(il.CompareSignedGreaterEqual(4, R(il, rm.reg), C(il, 0)), tPos, tNeg));

	/* positive: Rn <<= Rm */
	il.MarkLabel(tPos);
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ShiftLeft(4, R(il, rn.reg), il.LowPart(1, R(il, rm.reg)))));
	il.AddInstruction(il.Goto(tDone));

	/* negative */
	il.MarkLabel(tNeg);
	il.AddInstruction(
		il.If(il.CompareEqual(4, R(il, rm.reg), C(il, (int64_t)(uint32_t)(-32 & 0xFFFFFFFF))), tNeg32, tNegShift));

	il.MarkLabel(tNeg32);
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ArithShiftRight(4, R(il, rn.reg), il.Const(1, 31))));
	il.AddInstruction(il.Goto(tDone));

	il.MarkLabel(tNegShift);
	il.AddInstruction(
		il.SetRegister(4, rn.reg, il.ArithShiftRight(4, R(il, rn.reg), il.LowPart(1, il.Neg(4, R(il, rm.reg))))));
	il.AddInstruction(il.Goto(tDone));

	il.MarkLabel(tDone);
}

static void LiftShld(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	LowLevelILLabel tPos, tNeg, tDone, tNeg32, tNegShift;

	il.AddInstruction(il.If(il.CompareSignedGreaterEqual(4, R(il, rm.reg), C(il, 0)), tPos, tNeg));

	il.MarkLabel(tPos);
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ShiftLeft(4, R(il, rn.reg), il.LowPart(1, R(il, rm.reg)))));
	il.AddInstruction(il.Goto(tDone));

	il.MarkLabel(tNeg);
	il.AddInstruction(
		il.If(il.CompareEqual(4, R(il, rm.reg), C(il, (int64_t)(uint32_t)(-32 & 0xFFFFFFFF))), tNeg32, tNegShift));

	il.MarkLabel(tNeg32);
	il.AddInstruction(il.SetRegister(4, rn.reg, C(il, 0)));
	il.AddInstruction(il.Goto(tDone));

	il.MarkLabel(tNegShift);
	il.AddInstruction(
		il.SetRegister(4, rn.reg, il.LogicalShiftRight(4, R(il, rn.reg), il.LowPart(1, il.Neg(4, R(il, rm.reg))))));
	il.AddInstruction(il.Goto(tDone));

	il.MarkLabel(tDone);
}

static void LiftRotl(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	ExprId msb = il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 0x80000000)), C(il, 0));
	SetT(il, msb);
	il.AddInstruction(il.SetRegister(
		4, rn.reg, il.Or(4, il.ShiftLeft(4, R(il, rn.reg), il.Const(1, 1)), il.BoolToInt(4, FlagT(il)))));
}

static void LiftRotr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	ExprId lsb = il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 1)), C(il, 0));
	SetT(il, lsb);
	il.AddInstruction(il.SetRegister(4, rn.reg,
		il.Or(4, il.LogicalShiftRight(4, R(il, rn.reg), il.Const(1, 1)),
			il.ShiftLeft(4, il.BoolToInt(4, FlagT(il)), il.Const(1, 31)))));
}

static void LiftRotcl(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	uint32_t t0 = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, t0, il.BoolToInt(4, FlagT(il))));
	SetT(il, il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 0x80000000)), C(il, 0)));
	il.AddInstruction(
		il.SetRegister(4, rn.reg, il.Or(4, il.ShiftLeft(4, R(il, rn.reg), il.Const(1, 1)), il.Register(4, t0))));
}

static void LiftRotcr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	uint32_t t0 = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, t0, il.BoolToInt(4, FlagT(il))));
	SetT(il, il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 1)), C(il, 0)));
	il.AddInstruction(il.SetRegister(4, rn.reg,
		il.Or(4, il.LogicalShiftRight(4, R(il, rn.reg), il.Const(1, 1)),
			il.ShiftLeft(4, il.Register(4, t0), il.Const(1, 31)))));
}

/* ── extension / swap / extract ──────────────────────────────────────── */

static void LiftExtuB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ZeroExtend(4, il.LowPart(1, R(il, rm.reg)))));
}

static void LiftExtuW(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.ZeroExtend(4, il.LowPart(2, R(il, rm.reg)))));
}

static void LiftExtsB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.SignExtend(4, il.LowPart(1, R(il, rm.reg)))));
}

static void LiftExtsW(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	il.AddInstruction(il.SetRegister(4, rn.reg, il.SignExtend(4, il.LowPart(2, R(il, rm.reg)))));
}

static void LiftSwapB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	ExprId hi = il.And(4, R(il, rm.reg), C(il, 0xFFFF0000));
	ExprId loByte = il.And(4, R(il, rm.reg), C(il, 0xFF));
	ExprId hiByte = il.And(4, R(il, rm.reg), C(il, 0xFF00));
	ExprId result = il.Or(
		4, hi, il.Or(4, il.ShiftLeft(4, loByte, il.Const(1, 8)), il.LogicalShiftRight(4, hiByte, il.Const(1, 8))));
	il.AddInstruction(il.SetRegister(4, rn.reg, result));
}

static void LiftSwapW(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	ExprId lo = il.ShiftLeft(4, R(il, rm.reg), il.Const(1, 16));
	ExprId hi = il.LogicalShiftRight(4, R(il, rm.reg), il.Const(1, 16));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Or(4, lo, hi)));
}

static void LiftXtrct(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	ExprId hi = il.ShiftLeft(4, R(il, rm.reg), il.Const(1, 16));
	ExprId lo = il.LogicalShiftRight(4, R(il, rn.reg), il.Const(1, 16));
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Or(4, hi, lo)));
}

/* ── branches / control flow ─────────────────────────────────────────── */

static void LiftBra(const SH4Instruction& insn, LowLevelILFunction& il, Architecture* arch)
{
	uint64_t target = insn.target;
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label)
		il.AddInstruction(il.Goto(*label));
	else
		il.AddInstruction(il.Jump(il.ConstPointer(4, target)));
}

static void LiftBsr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.AddInstruction(il.Call(il.ConstPointer(4, insn.target)));
}

static void LiftBt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	LowLevelILLabel tLabel, fLabel;
	il.AddInstruction(il.If(FlagT(il), tLabel, fLabel));
	il.MarkLabel(tLabel);
	il.AddInstruction(il.Jump(il.ConstPointer(4, insn.target)));
	il.MarkLabel(fLabel);
}

static void LiftBf(const SH4Instruction& insn, LowLevelILFunction& il)
{
	LowLevelILLabel tLabel, fLabel;
	il.AddInstruction(il.If(FlagT(il), fLabel, tLabel));
	il.MarkLabel(tLabel);
	il.AddInstruction(il.Jump(il.ConstPointer(4, insn.target)));
	il.MarkLabel(fLabel);
}

static void LiftJmp(const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.AddInstruction(il.Jump(R(il, insn.ops[0].reg)));
}

static void LiftJsr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.AddInstruction(il.Call(R(il, insn.ops[0].reg)));
}

static void LiftBraf(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	il.AddInstruction(il.Jump(il.Add(4, C(il, (int64_t)(insn.addr + 4)), R(il, rn.reg))));
}

static void LiftBsrf(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	il.AddInstruction(il.Call(il.Add(4, C(il, (int64_t)(insn.addr + 4)), R(il, rn.reg))));
}

static void LiftRts(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.Return(R(il, REG_PR)));
}

static void LiftRte(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.Return(R(il, REG_SPC)));
}

static void LiftTrapa(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.SystemCall());
}

/* ── system register transfers ───────────────────────────────────────── */

static void LiftSts(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	WriteReg(il, dst, ReadOp(il, src));
}

static void LiftStsL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	PreDec(il, dst, 4);
	il.AddInstruction(il.Store(4, MemAddr(il, dst), ReadOp(il, src)));
}

static void LiftLds(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	WriteReg(il, dst, ReadOp(il, src));
}

static void LiftLdsL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	ExprId val = il.Load(4, MemAddr(il, src));
	WriteReg(il, dst, val);
	PostInc(il, src, 4);
}

static void LiftStc(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	WriteReg(il, dst, ReadOp(il, src));
}

static void LiftStcL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	PreDec(il, dst, 4);
	il.AddInstruction(il.Store(4, MemAddr(il, dst), ReadOp(il, src)));
}

static void LiftLdc(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	WriteReg(il, dst, ReadOp(il, src));
}

static void LiftLdcL(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	ExprId val = il.Load(4, MemAddr(il, src));
	WriteReg(il, dst, val);
	PostInc(il, src, 4);
}

/* ── division ────────────────────────────────────────────────────────── */

static void LiftDiv0s(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	SetQ(il, il.CompareNotEqual(4, il.And(4, R(il, rn.reg), C(il, 0x80000000)), C(il, 0)));
	SetM(il, il.CompareNotEqual(4, il.And(4, R(il, rm.reg), C(il, 0x80000000)), C(il, 0)));
	SetT(il,
		il.CompareNotEqual(
			4, il.And(4, R(il, rn.reg), C(il, 0x80000000)), il.And(4, R(il, rm.reg), C(il, 0x80000000))));
}

static void LiftDiv0u(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	SetM(il, il.Const(0, 0));
	SetQ(il, il.Const(0, 0));
	SetT(il, il.Const(0, 0));
}

static void LiftDiv1(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rm = insn.ops[0];
	const auto& rn = insn.ops[1];
	uint32_t t0 = LLIL_TEMP(0);
	/* Rn = (Rn << 1) | T */
	il.AddInstruction(
		il.SetRegister(4, t0, il.Or(4, il.ShiftLeft(4, R(il, rn.reg), il.Const(1, 1)), il.BoolToInt(4, FlagT(il)))));
	/* Approximate: Rn = tmp - Rm */
	il.AddInstruction(il.SetRegister(4, rn.reg, il.Sub(4, il.Register(4, t0), R(il, rm.reg))));
	/* T = approximate comparison */
	SetT(il, il.CompareUnsignedGreaterEqual(4, il.Register(4, t0), R(il, rm.reg)));
}

/* ── misc ────────────────────────────────────────────────────────────── */

static void LiftClrt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	SetT(il, il.Const(0, 0));
}

static void LiftSett(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	SetT(il, il.Const(0, 1));
}

static void LiftClrmac(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.SetRegister(4, REG_MACH, C(il, 0)));
	il.AddInstruction(il.SetRegister(4, REG_MACL, C(il, 0)));
}

static void LiftTasB(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& rn = insn.ops[0];
	ExprId addr = R(il, rn.reg);
	uint32_t t0 = LLIL_TEMP(0);
	il.AddInstruction(il.SetRegister(4, t0, il.ZeroExtend(4, il.Load(1, addr))));
	SetT(il, il.CompareEqual(4, il.Register(4, t0), C(il, 0)));
	il.AddInstruction(il.Store(1, R(il, rn.reg), il.Or(1, il.LowPart(1, il.Register(4, t0)), il.Const(1, 0x80))));
}

/* ── FPU ─────────────────────────────────────────────────────────────── */

static void LiftFmov(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FrSize(src);
	if (FrSize(dst) > sz)
		sz = FrSize(dst);

	size_t srcSz = is_mem_type(src.type) ? sz : sz;
	size_t dstSz = is_mem_type(dst.type) ? sz : sz;

	if (is_mem_type(dst.type))
	{
		/* Store */
		PreDec(il, dst, dstSz);
		ExprId addr = MemAddr(il, dst);
		ExprId val;
		if (src.type == OpType::FR_REG || src.type == OpType::DR_REG || src.type == OpType::XD_REG
			|| src.type == OpType::XF_REG)
			val = il.Register(srcSz, src.reg);
		else
			val = ReadOp(il, src);
		il.AddInstruction(il.Store(dstSz, addr, val));
		PostInc(il, src, srcSz);
	}
	else if (dst.type == OpType::FR_REG || dst.type == OpType::DR_REG || dst.type == OpType::XD_REG
		|| dst.type == OpType::XF_REG)
	{
		if (is_mem_type(src.type))
		{
			/* Load */
			PreDec(il, src, srcSz);
			ExprId addr = MemAddr(il, src);
			ExprId val = il.Load(srcSz, addr);
			il.AddInstruction(il.SetRegister(FrSize(dst), dst.reg, val));
			PostInc(il, src, srcSz);
		}
		else if (src.type == OpType::FR_REG || src.type == OpType::DR_REG || src.type == OpType::XD_REG
			|| src.type == OpType::XF_REG)
		{
			/* Register to register */
			il.AddInstruction(il.SetRegister(FrSize(dst), dst.reg, il.Register(FrSize(src), src.reg)));
		}
		else
		{
			il.AddInstruction(il.SetRegister(FrSize(dst), dst.reg, ReadOp(il, src)));
		}
	}
	else
	{
		il.AddInstruction(il.Unimplemented());
	}
}

static void LiftFadd(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FopSize(insn);
	il.AddInstruction(il.SetRegister(sz, dst.reg, il.FloatAdd(sz, Fr(il, dst), Fr(il, src))));
}

static void LiftFsub(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FopSize(insn);
	il.AddInstruction(il.SetRegister(sz, dst.reg, il.FloatSub(sz, Fr(il, dst), Fr(il, src))));
}

static void LiftFmul(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FopSize(insn);
	il.AddInstruction(il.SetRegister(sz, dst.reg, il.FloatMult(sz, Fr(il, dst), Fr(il, src))));
}

static void LiftFdiv(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FopSize(insn);
	il.AddInstruction(il.SetRegister(sz, dst.reg, il.FloatDiv(sz, Fr(il, dst), Fr(il, src))));
}

static void LiftFsqrt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& op = insn.ops[0];
	size_t sz = FrSize(op);
	il.AddInstruction(il.SetRegister(sz, op.reg, il.FloatSqrt(sz, Fr(il, op))));
}

static void LiftFabs(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& op = insn.ops[0];
	size_t sz = FrSize(op);
	il.AddInstruction(il.SetRegister(sz, op.reg, il.FloatAbs(sz, Fr(il, op))));
}

static void LiftFneg(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& op = insn.ops[0];
	size_t sz = FrSize(op);
	il.AddInstruction(il.SetRegister(sz, op.reg, il.FloatNeg(sz, Fr(il, op))));
}

static void LiftFloat(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FLOAT FPUL, FRn/DRn — int→float */
	const auto& dst = (insn.op_count == 1) ? insn.ops[0] : insn.ops[1];
	size_t sz = FrSize(dst);
	il.AddInstruction(il.SetRegister(sz, dst.reg, il.IntToFloat(sz, R(il, REG_FPUL))));
}

static void LiftFtrc(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FTRC FRn/DRn, FPUL — float→int (truncate) */
	const auto& src = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, REG_FPUL, il.FloatToInt(4, Fr(il, src))));
}

static void LiftFcmpEq(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FopSize(insn);
	SetT(il, il.FloatCompareEqual(sz, Fr(il, dst), Fr(il, src)));
}

static void LiftFcmpGt(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& src = insn.ops[0];
	const auto& dst = insn.ops[1];
	size_t sz = FopSize(insn);
	SetT(il, il.FloatCompareGreaterThan(sz, Fr(il, dst), Fr(il, src)));
}

static void LiftFlds(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FLDS FRn, FPUL — FPUL = FRn */
	const auto& src = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, REG_FPUL, il.Register(4, src.reg)));
}

static void LiftFsts(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FSTS FPUL, FRn — FRn = FPUL */
	const auto& dst = (insn.op_count == 1) ? insn.ops[0] : insn.ops[1];
	il.AddInstruction(il.SetRegister(4, dst.reg, R(il, REG_FPUL)));
}

static void LiftFschg(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.SetRegister(4, REG_FPSCR, il.Xor(4, R(il, REG_FPSCR), C(il, 1 << 20))));
}

static void LiftFrchg(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.SetRegister(4, REG_FPSCR, il.Xor(4, R(il, REG_FPSCR), C(il, 1 << 21))));
}

static void LiftFldi0(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& dst = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, dst.reg, il.FloatConstSingle(0.0f)));
}

static void LiftFldi1(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& dst = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, dst.reg, il.FloatConstSingle(1.0f)));
}

static void LiftFcnvsd(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FCNVSD FPUL, DRn — single→double */
	const auto& dst = insn.ops[1];
	il.AddInstruction(il.SetRegister(8, dst.reg, il.FloatConvert(8, il.Register(4, REG_FPUL))));
}

static void LiftFcnvds(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FCNVDS DRm, FPUL — double→single */
	const auto& src = insn.ops[0];
	il.AddInstruction(il.SetRegister(4, REG_FPUL, il.FloatConvert(4, il.Register(8, src.reg))));
}

static void LiftFmac(const SH4Instruction& insn, LowLevelILFunction& il)
{
	/* FMAC FR0, FRm, FRn — FRn = FR0*FRm + FRn */
	const auto& rm = insn.ops[1];
	const auto& rn = insn.ops[2];
	il.AddInstruction(il.SetRegister(4, rn.reg,
		il.FloatAdd(4, il.FloatMult(4, il.Register(4, REG_FR0), il.Register(4, rm.reg)), il.Register(4, rn.reg))));
}

static void LiftFsrra(const SH4Instruction& insn, LowLevelILFunction& il)
{
	const auto& op = insn.ops[0];
	il.AddInstruction(
		il.SetRegister(4, op.reg, il.FloatDiv(4, il.FloatConstSingle(1.0f), il.FloatSqrt(4, il.Register(4, op.reg)))));
}

static void LiftFipr(const SH4Instruction& insn, LowLevelILFunction& il)
{
	uint32_t m_base = REG_FR0 + (insn.ops[0].reg - REG_FV0) * 4;
	uint32_t n_base = REG_FR0 + (insn.ops[1].reg - REG_FV0) * 4;
	ExprId sum = il.FloatAdd(4,
		il.FloatAdd(4, il.FloatMult(4, il.Register(4, m_base), il.Register(4, n_base)),
			il.FloatMult(4, il.Register(4, m_base + 1), il.Register(4, n_base + 1))),
		il.FloatAdd(4, il.FloatMult(4, il.Register(4, m_base + 2), il.Register(4, n_base + 2)),
			il.FloatMult(4, il.Register(4, m_base + 3), il.Register(4, n_base + 3))));
	il.AddInstruction(il.SetRegister(4, n_base + 3, sum));
}

static void LiftFtrv(const SH4Instruction& insn, LowLevelILFunction& il)
{
	uint32_t n_base = REG_FR0 + (insn.ops[0].reg - REG_FV0) * 4;
	/* Save input vector to temps (output overwrites same registers) */
	for (int i = 0; i < 4; i++)
		il.AddInstruction(il.SetRegister(4, LLIL_TEMP(i), il.Register(4, n_base + i)));
	/* Compute each result row */
	for (int row = 0; row < 4; row++)
	{
		ExprId sum = il.FloatAdd(4,
			il.FloatAdd(4, il.FloatMult(4, il.Register(4, REG_XF0 + row), il.Register(4, LLIL_TEMP(0))),
				il.FloatMult(4, il.Register(4, REG_XF0 + 4 + row), il.Register(4, LLIL_TEMP(1)))),
			il.FloatAdd(4, il.FloatMult(4, il.Register(4, REG_XF0 + 8 + row), il.Register(4, LLIL_TEMP(2))),
				il.FloatMult(4, il.Register(4, REG_XF0 + 12 + row), il.Register(4, LLIL_TEMP(3)))));
		il.AddInstruction(il.SetRegister(4, n_base + row, sum));
	}
}

static void LiftFsca(const SH4Instruction& insn, LowLevelILFunction& il)
{
	uint32_t fr_n = REG_FR0 + (insn.ops[1].reg - REG_DR0) * 2;
	il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(fr_n), RegisterOrFlag::Register(fr_n + 1)}, INTRINSIC_FSCA,
		{il.Register(4, REG_FPUL)}));
}

static void LiftSleep(const SH4Instruction& insn, LowLevelILFunction& il)
{
	(void)insn;
	il.AddInstruction(il.Intrinsic({}, INTRINSIC_SLEEP, {}));
}

/* ── public entry point ──────────────────────────────────────────────── */

bool sh4_lift(Architecture* arch, const SH4Instruction& insn, LowLevelILFunction& il)
{
	il.SetCurrentAddress(arch, insn.addr);

	switch (insn.mn)
	{
	/* ── data movement ─────────────────────────────────────────────── */
	case Mnemonic::MOV:
		LiftMov(insn, il);
		break;
	case Mnemonic::MOV_B:
		LiftMovMem(insn, il, 1);
		break;
	case Mnemonic::MOV_W:
		LiftMovMem(insn, il, 2);
		break;
	case Mnemonic::MOV_L:
		LiftMovMem(insn, il, 4);
		break;
	case Mnemonic::MOVA:
		LiftMova(insn, il);
		break;
	case Mnemonic::MOVT:
		LiftMovt(insn, il);
		break;
	case Mnemonic::MOVCA_L:
		LiftMovcaL(insn, il);
		break;

	/* ── arithmetic ────────────────────────────────────────────────── */
	case Mnemonic::ADD:
		LiftAdd(insn, il);
		break;
	case Mnemonic::ADDC:
		LiftAddc(insn, il);
		break;
	case Mnemonic::ADDV:
		LiftAddv(insn, il);
		break;
	case Mnemonic::SUB:
		LiftSub(insn, il);
		break;
	case Mnemonic::SUBC:
		LiftSubc(insn, il);
		break;
	case Mnemonic::SUBV:
		LiftSubv(insn, il);
		break;
	case Mnemonic::NEG:
		LiftNeg(insn, il);
		break;
	case Mnemonic::NEGC:
		LiftNegc(insn, il);
		break;
	case Mnemonic::DT:
		LiftDt(insn, il);
		break;
	case Mnemonic::MUL_L:
		LiftMulL(insn, il);
		break;
	case Mnemonic::MULS_W:
		LiftMulsW(insn, il);
		break;
	case Mnemonic::MULU_W:
		LiftMuluW(insn, il);
		break;
	case Mnemonic::DMULS_L:
		LiftDmulsL(insn, il);
		break;
	case Mnemonic::DMULU_L:
		LiftDmuluL(insn, il);
		break;
	case Mnemonic::MAC_L:
		LiftMacL(insn, il);
		break;
	case Mnemonic::MAC_W:
		LiftMacW(insn, il);
		break;

	/* ── comparison ────────────────────────────────────────────────── */
	case Mnemonic::CMP_EQ:
		LiftCmpEq(insn, il);
		break;
	case Mnemonic::CMP_GE:
		LiftCmpGe(insn, il);
		break;
	case Mnemonic::CMP_GT:
		LiftCmpGt(insn, il);
		break;
	case Mnemonic::CMP_HS:
		LiftCmpHs(insn, il);
		break;
	case Mnemonic::CMP_HI:
		LiftCmpHi(insn, il);
		break;
	case Mnemonic::CMP_PL:
		LiftCmpPl(insn, il);
		break;
	case Mnemonic::CMP_PZ:
		LiftCmpPz(insn, il);
		break;
	case Mnemonic::CMP_STR:
		LiftCmpStr(insn, il);
		break;
	case Mnemonic::TST:
		LiftTst(insn, il);
		break;
	case Mnemonic::TST_B:
		LiftTstB(insn, il);
		break;

	/* ── logic ─────────────────────────────────────────────────────── */
	case Mnemonic::AND:
		LiftAnd(insn, il);
		break;
	case Mnemonic::OR:
		LiftOr(insn, il);
		break;
	case Mnemonic::XOR:
		LiftXor(insn, il);
		break;
	case Mnemonic::NOT:
		LiftNot(insn, il);
		break;
	case Mnemonic::AND_B:
		LiftAndB(insn, il);
		break;
	case Mnemonic::OR_B:
		LiftOrB(insn, il);
		break;
	case Mnemonic::XOR_B:
		LiftXorB(insn, il);
		break;

	/* ── shifts with T ─────────────────────────────────────────────── */
	case Mnemonic::SHLL:
		LiftShll(insn, il);
		break;
	case Mnemonic::SHLR:
		LiftShlr(insn, il);
		break;
	case Mnemonic::SHAL:
		LiftShll(insn, il);
		break; /* same as SHLL */
	case Mnemonic::SHAR:
		LiftShar(insn, il);
		break;

	/* ── shifts constant ───────────────────────────────────────────── */
	case Mnemonic::SHLL2:
		LiftShllN(insn, il, 2);
		break;
	case Mnemonic::SHLL8:
		LiftShllN(insn, il, 8);
		break;
	case Mnemonic::SHLL16:
		LiftShllN(insn, il, 16);
		break;
	case Mnemonic::SHLR2:
		LiftShlrN(insn, il, 2);
		break;
	case Mnemonic::SHLR8:
		LiftShlrN(insn, il, 8);
		break;
	case Mnemonic::SHLR16:
		LiftShlrN(insn, il, 16);
		break;

	/* ── dynamic shifts ────────────────────────────────────────────── */
	case Mnemonic::SHAD:
		LiftShad(insn, il);
		break;
	case Mnemonic::SHLD:
		LiftShld(insn, il);
		break;

	/* ── rotates ───────────────────────────────────────────────────── */
	case Mnemonic::ROTL:
		LiftRotl(insn, il);
		break;
	case Mnemonic::ROTR:
		LiftRotr(insn, il);
		break;
	case Mnemonic::ROTCL:
		LiftRotcl(insn, il);
		break;
	case Mnemonic::ROTCR:
		LiftRotcr(insn, il);
		break;

	/* ── extension / swap ──────────────────────────────────────────── */
	case Mnemonic::EXTU_B:
		LiftExtuB(insn, il);
		break;
	case Mnemonic::EXTU_W:
		LiftExtuW(insn, il);
		break;
	case Mnemonic::EXTS_B:
		LiftExtsB(insn, il);
		break;
	case Mnemonic::EXTS_W:
		LiftExtsW(insn, il);
		break;
	case Mnemonic::SWAP_B:
		LiftSwapB(insn, il);
		break;
	case Mnemonic::SWAP_W:
		LiftSwapW(insn, il);
		break;
	case Mnemonic::XTRCT:
		LiftXtrct(insn, il);
		break;

	/* ── branches ──────────────────────────────────────────────────── */
	case Mnemonic::BRA:
		LiftBra(insn, il, arch);
		break;
	case Mnemonic::BSR:
		LiftBsr(insn, il);
		break;
	case Mnemonic::BT:
		LiftBt(insn, il);
		break;
	case Mnemonic::BF:
		LiftBf(insn, il);
		break;
	case Mnemonic::BT_S:
		LiftBt(insn, il);
		break; /* delay slot handled by arch */
	case Mnemonic::BF_S:
		LiftBf(insn, il);
		break; /* delay slot handled by arch */
	case Mnemonic::JMP:
		LiftJmp(insn, il);
		break;
	case Mnemonic::JSR:
		LiftJsr(insn, il);
		break;
	case Mnemonic::BRAF:
		LiftBraf(insn, il);
		break;
	case Mnemonic::BSRF:
		LiftBsrf(insn, il);
		break;
	case Mnemonic::RTS:
		LiftRts(insn, il);
		break;
	case Mnemonic::RTE:
		LiftRte(insn, il);
		break;
	case Mnemonic::TRAPA:
		LiftTrapa(insn, il);
		break;

	/* ── system register transfers ─────────────────────────────────── */
	case Mnemonic::STS:
		LiftSts(insn, il);
		break;
	case Mnemonic::STS_L:
		LiftStsL(insn, il);
		break;
	case Mnemonic::LDS:
		LiftLds(insn, il);
		break;
	case Mnemonic::LDS_L:
		LiftLdsL(insn, il);
		break;
	case Mnemonic::STC:
		LiftStc(insn, il);
		break;
	case Mnemonic::STC_L:
		LiftStcL(insn, il);
		break;
	case Mnemonic::LDC:
		LiftLdc(insn, il);
		break;
	case Mnemonic::LDC_L:
		LiftLdcL(insn, il);
		break;

	/* ── division ──────────────────────────────────────────────────── */
	case Mnemonic::DIV0S:
		LiftDiv0s(insn, il);
		break;
	case Mnemonic::DIV0U:
		LiftDiv0u(insn, il);
		break;
	case Mnemonic::DIV1:
		LiftDiv1(insn, il);
		break;

	/* ── misc ──────────────────────────────────────────────────────── */
	case Mnemonic::CLRT:
		LiftClrt(insn, il);
		break;
	case Mnemonic::SETT:
		LiftSett(insn, il);
		break;
	case Mnemonic::CLRMAC:
		LiftClrmac(insn, il);
		break;
	case Mnemonic::TAS_B:
		LiftTasB(insn, il);
		break;
	case Mnemonic::CLRS:
		SetT(il, il.Const(1, 0));
		break; /* clear S flag — approx as T=0 */
	case Mnemonic::SETS:
		SetT(il, il.Const(1, 1));
		break; /* set S flag — approx as T=1 */

	/* ── FPU ───────────────────────────────────────────────────────── */
	case Mnemonic::FMOV:
	case Mnemonic::FMOV_S:
	case Mnemonic::FMOV_D:
		LiftFmov(insn, il);
		break;
	case Mnemonic::FADD:
		LiftFadd(insn, il);
		break;
	case Mnemonic::FSUB:
		LiftFsub(insn, il);
		break;
	case Mnemonic::FMUL:
		LiftFmul(insn, il);
		break;
	case Mnemonic::FDIV:
		LiftFdiv(insn, il);
		break;
	case Mnemonic::FSQRT:
		LiftFsqrt(insn, il);
		break;
	case Mnemonic::FABS:
		LiftFabs(insn, il);
		break;
	case Mnemonic::FNEG:
		LiftFneg(insn, il);
		break;
	case Mnemonic::FLOAT_OP:
		LiftFloat(insn, il);
		break;
	case Mnemonic::FTRC:
		LiftFtrc(insn, il);
		break;
	case Mnemonic::FCMP_EQ:
		LiftFcmpEq(insn, il);
		break;
	case Mnemonic::FCMP_GT:
		LiftFcmpGt(insn, il);
		break;
	case Mnemonic::FLDS:
		LiftFlds(insn, il);
		break;
	case Mnemonic::FSTS:
		LiftFsts(insn, il);
		break;
	case Mnemonic::FSCHG:
		LiftFschg(insn, il);
		break;
	case Mnemonic::FRCHG:
		LiftFrchg(insn, il);
		break;
	case Mnemonic::FLDI0:
		LiftFldi0(insn, il);
		break;
	case Mnemonic::FLDI1:
		LiftFldi1(insn, il);
		break;
	case Mnemonic::FCNVSD:
		LiftFcnvsd(insn, il);
		break;
	case Mnemonic::FCNVDS:
		LiftFcnvds(insn, il);
		break;
	case Mnemonic::FMAC:
		LiftFmac(insn, il);
		break;

	/* ── NOP-like ──────────────────────────────────────────────────── */
	case Mnemonic::NOP:
	case Mnemonic::PREF:
	case Mnemonic::OCBI:
	case Mnemonic::OCBP:
	case Mnemonic::OCBWB:
	case Mnemonic::LDTLB:
		il.AddInstruction(il.Nop());
		break;

	/* ── FPU vector/matrix/special ─────────────────────────────────── */
	case Mnemonic::FIPR:
		LiftFipr(insn, il);
		break;
	case Mnemonic::FTRV:
		LiftFtrv(insn, il);
		break;
	case Mnemonic::FSRRA:
		LiftFsrra(insn, il);
		break;
	case Mnemonic::FSCA:
		LiftFsca(insn, il);
		break;
	case Mnemonic::SLEEP:
		LiftSleep(insn, il);
		break;

	/* ── fallback ──────────────────────────────────────────────────── */
	default:
		il.AddInstruction(il.Unimplemented());
		return false;
	}
	return true;
}
