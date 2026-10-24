/*  SH-4 instruction decoder — faithful port of superbiHnja/sh4_decode.py.
 *
 *  Every instruction that the Python decoder handles is decoded identically
 *  here: same mnemonic, operands, branch kind, delay-slot flag and target.
 */

#include "sh4_decode.h"
#include <initializer_list>

namespace {

	/* ── Sign extension ──────────────────────────────────────────────── */

	inline int32_t se8(uint32_t v)
	{
		return static_cast<int8_t>(static_cast<uint8_t>(v));
	}

	inline int32_t se12(uint32_t v)
	{
		return (v & 0x800) ? static_cast<int32_t>(v | 0xFFFFF000u) : static_cast<int32_t>(v);
	}

	/* ── Register helpers ────────────────────────────────────────────── */

	inline SH4Reg rn(uint32_t n)
	{
		return static_cast<SH4Reg>(REG_R0 + n);
	}
	inline SH4Reg frn(uint32_t n)
	{
		return static_cast<SH4Reg>(REG_FR0 + n);
	}
	inline SH4Reg drn(uint32_t n)
	{
		return static_cast<SH4Reg>(REG_DR0 + (n >> 1));
	}
	inline SH4Reg fvn(uint32_t n)
	{
		return static_cast<SH4Reg>(REG_FV0 + (n >> 2));
	}
	inline SH4Reg bank_r(uint32_t n)
	{
		return static_cast<SH4Reg>(REG_R0_BANK + (n & 7));
	}

	/* Map encoding field → control register.  Returns REG_COUNT on miss. */
	inline SH4Reg ctrl_reg(uint32_t m)
	{
		switch (m)
		{
		case 0:
			return REG_SR;
		case 1:
			return REG_GBR;
		case 2:
			return REG_VBR;
		case 3:
			return REG_SSR;
		case 4:
			return REG_SPC;
		default:
			return REG_COUNT;
		}
	}

	/* Map encoding field → system register.  Returns REG_COUNT on miss. */
	inline SH4Reg sys_reg(uint32_t m)
	{
		switch (m)
		{
		case 0:
			return REG_MACH;
		case 1:
			return REG_MACL;
		case 2:
			return REG_PR;
		case 5:
			return REG_FPUL;
		case 6:
			return REG_FPSCR;
		default:
			return REG_COUNT;
		}
	}

	/* ── Operand constructors ────────────────────────────────────────── */
	/*    Each returns a stack-allocated SH4Operand — zero cost.           */

	inline SH4Operand oR(uint32_t n)
	{
		return {OpType::REG, rn(n)};
	}

	inline SH4Operand oI(int32_t v)
	{
		return {OpType::IMM, REG_R0, REG_R0, v};
	}

	inline SH4Operand oCR(SH4Reg r)
	{
		return {OpType::CTRL_REG, r};
	}

	inline SH4Operand oSR(SH4Reg r)
	{
		return {OpType::SYS_REG, r};
	}

	inline SH4Operand oFR(uint32_t n)
	{
		return {OpType::FR_REG, frn(n)};
	}

	inline SH4Operand oDR(uint32_t n)
	{
		return {OpType::DR_REG, drn(n & 0xE)};
	}

	inline SH4Operand oFV(uint32_t n)
	{
		return {OpType::FV_REG, fvn(n)};
	}

	inline SH4Operand oAT(uint32_t n)
	{
		return {OpType::AT_REG, rn(n)};
	}

	inline SH4Operand oATP(uint32_t n)
	{
		return {OpType::AT_REG_POST, rn(n)};
	}

	inline SH4Operand oATM(uint32_t n)
	{
		return {OpType::AT_PRE_REG, rn(n)};
	}

	inline SH4Operand oAR0(uint32_t n)
	{
		return {OpType::AT_R0_REG, rn(n), rn(n)};
	}

	inline SH4Operand oADDR(uint32_t a)
	{
		return {OpType::ADDR, REG_R0, REG_R0, static_cast<int32_t>(a)};
	}

	inline SH4Operand oDPC(uint32_t a)
	{
		return {OpType::DISP_PC, REG_R0, REG_R0, static_cast<int32_t>(a)};
	}

	inline SH4Operand oDREG(uint32_t n, int32_t d)
	{
		return {OpType::DISP_REG, rn(n), rn(n), d};
	}

	inline SH4Operand oDGBR(int32_t d)
	{
		return {OpType::DISP_GBR, REG_GBR, REG_GBR, d};
	}

	inline SH4Operand oR0GBR()
	{
		return {OpType::AT_R0_GBR};
	}

	inline SH4Operand oBANK(uint32_t m)
	{
		return {OpType::REG, bank_r(m)};
	}

	/* ── Instruction setters ─────────────────────────────────────────── */

	static void S(SH4Instruction& i, Mnemonic mn, std::initializer_list<SH4Operand> ops,
		BranchKind br = BranchKind::NONE, bool delay = false)
	{
		i.mn = mn;
		i.op_count = 0;
		for (const auto& op : ops)
			i.ops[i.op_count++] = op;
		i.branch = br;
		i.has_delay = delay;
	}

	/* Same as S() but also records a resolved branch target. */
	static void ST(SH4Instruction& i, Mnemonic mn, std::initializer_list<SH4Operand> ops, BranchKind br, bool delay,
		uint32_t target)
	{
		S(i, mn, ops, br, delay);
		i.has_target = true;
		i.target = target;
	}

	/* ── Group 0: 0000nnnnmmmmdddd ───────────────────────────────────── */

	static void g0(SH4Instruction& i, uint16_t raw, uint32_t n, uint32_t m, uint32_t d)
	{
		uint32_t lo = raw & 0xFF;
		switch (d)
		{
		case 0x4:
			S(i, Mnemonic::MOV_B, {oR(m), oAR0(n)});
			return;
		case 0x5:
			S(i, Mnemonic::MOV_W, {oR(m), oAR0(n)});
			return;
		case 0x6:
			S(i, Mnemonic::MOV_L, {oR(m), oAR0(n)});
			return;
		case 0x7:
			S(i, Mnemonic::MUL_L, {oR(m), oR(n)});
			return;
		case 0xC:
			S(i, Mnemonic::MOV_B, {oAR0(m), oR(n)});
			return;
		case 0xD:
			S(i, Mnemonic::MOV_W, {oAR0(m), oR(n)});
			return;
		case 0xE:
			S(i, Mnemonic::MOV_L, {oAR0(m), oR(n)});
			return;
		case 0xF:
			S(i, Mnemonic::MAC_L, {oATP(m), oATP(n)});
			return;
		case 0x3:
			switch (m)
			{
			case 0x0:
				S(i, Mnemonic::BSRF, {oR(n)}, BranchKind::CALL_REG_DIRECT, true);
				return;
			case 0x2:
				S(i, Mnemonic::BRAF, {oR(n)}, BranchKind::UNCOND_INDIRECT, true);
				return;
			case 0x8:
				S(i, Mnemonic::PREF, {oAT(n)});
				return;
			case 0x9:
				S(i, Mnemonic::OCBI, {oAT(n)});
				return;
			case 0xA:
				S(i, Mnemonic::OCBP, {oAT(n)});
				return;
			case 0xB:
				S(i, Mnemonic::OCBWB, {oAT(n)});
				return;
			case 0xC:
				S(i, Mnemonic::MOVCA_L, {oR(0), oAT(n)});
				return;
			}
			return;
		case 0x2:
			if (m >= 8)
				S(i, Mnemonic::STC, {oBANK(m), oR(n)});
			else
			{
				SH4Reg cr = ctrl_reg(m);
				if (cr != REG_COUNT)
					S(i, Mnemonic::STC, {oCR(cr), oR(n)});
			}
			return;
		case 0xA:
			if (m == 3)
				S(i, Mnemonic::STC, {oCR(REG_SGR), oR(n)});
			else if (m == 0xF)
				S(i, Mnemonic::STC, {oCR(REG_DBR), oR(n)});
			else
			{
				SH4Reg sr = sys_reg(m);
				if (sr != REG_COUNT)
					S(i, Mnemonic::STS, {oSR(sr), oR(n)});
			}
			return;
		case 0x9:
			if (lo == 0x09)
				S(i, Mnemonic::NOP, {});
			else if (lo == 0x19)
				S(i, Mnemonic::DIV0U, {});
			else if (m == 2)
				S(i, Mnemonic::MOVT, {oR(n)});
			return;
		case 0x8:
			switch (lo)
			{
			case 0x08:
				S(i, Mnemonic::CLRT, {});
				return;
			case 0x18:
				S(i, Mnemonic::SETT, {});
				return;
			case 0x28:
				S(i, Mnemonic::CLRMAC, {});
				return;
			case 0x38:
				S(i, Mnemonic::LDTLB, {});
				return;
			case 0x48:
				S(i, Mnemonic::CLRS, {});
				return;
			case 0x58:
				S(i, Mnemonic::SETS, {});
				return;
			}
			return;
		case 0xB:
			if (raw == 0x000B)
				S(i, Mnemonic::RTS, {}, BranchKind::RETURN, true);
			else if (raw == 0x001B)
				S(i, Mnemonic::SLEEP, {});
			else if (raw == 0x002B)
				S(i, Mnemonic::RTE, {}, BranchKind::EXCEPTION_RETURN, true);
			return;
		}
	}

	/* ── Group 2: 0010nnnnmmmmdddd ───────────────────────────────────── */

	static void g2(SH4Instruction& i, uint32_t n, uint32_t m, uint32_t d)
	{
		switch (d)
		{
		case 0x0:
			S(i, Mnemonic::MOV_B, {oR(m), oAT(n)});
			break;
		case 0x1:
			S(i, Mnemonic::MOV_W, {oR(m), oAT(n)});
			break;
		case 0x2:
			S(i, Mnemonic::MOV_L, {oR(m), oAT(n)});
			break;
		case 0x4:
			S(i, Mnemonic::MOV_B, {oR(m), oATM(n)});
			break;
		case 0x5:
			S(i, Mnemonic::MOV_W, {oR(m), oATM(n)});
			break;
		case 0x6:
			S(i, Mnemonic::MOV_L, {oR(m), oATM(n)});
			break;
		case 0x7:
			S(i, Mnemonic::DIV0S, {oR(m), oR(n)});
			break;
		case 0x8:
			S(i, Mnemonic::TST, {oR(m), oR(n)});
			break;
		case 0x9:
			S(i, Mnemonic::AND, {oR(m), oR(n)});
			break;
		case 0xA:
			S(i, Mnemonic::XOR, {oR(m), oR(n)});
			break;
		case 0xB:
			S(i, Mnemonic::OR, {oR(m), oR(n)});
			break;
		case 0xC:
			S(i, Mnemonic::CMP_STR, {oR(m), oR(n)});
			break;
		case 0xD:
			S(i, Mnemonic::XTRCT, {oR(m), oR(n)});
			break;
		case 0xE:
			S(i, Mnemonic::MULU_W, {oR(m), oR(n)});
			break;
		case 0xF:
			S(i, Mnemonic::MULS_W, {oR(m), oR(n)});
			break;
			/* d==3: invalid — stays DOT_WORD */
		}
	}

	/* ── Group 3: 0011nnnnmmmmdddd ───────────────────────────────────── */

	static void g3(SH4Instruction& i, uint32_t n, uint32_t m, uint32_t d)
	{
		switch (d)
		{
		case 0x0:
			S(i, Mnemonic::CMP_EQ, {oR(m), oR(n)});
			break;
		case 0x2:
			S(i, Mnemonic::CMP_HS, {oR(m), oR(n)});
			break;
		case 0x3:
			S(i, Mnemonic::CMP_GE, {oR(m), oR(n)});
			break;
		case 0x4:
			S(i, Mnemonic::DIV1, {oR(m), oR(n)});
			break;
		case 0x5:
			S(i, Mnemonic::DMULU_L, {oR(m), oR(n)});
			break;
		case 0x6:
			S(i, Mnemonic::CMP_HI, {oR(m), oR(n)});
			break;
		case 0x7:
			S(i, Mnemonic::CMP_GT, {oR(m), oR(n)});
			break;
		case 0x8:
			S(i, Mnemonic::SUB, {oR(m), oR(n)});
			break;
		case 0xA:
			S(i, Mnemonic::SUBC, {oR(m), oR(n)});
			break;
		case 0xB:
			S(i, Mnemonic::SUBV, {oR(m), oR(n)});
			break;
		case 0xC:
			S(i, Mnemonic::ADD, {oR(m), oR(n)});
			break;
		case 0xD:
			S(i, Mnemonic::DMULS_L, {oR(m), oR(n)});
			break;
		case 0xE:
			S(i, Mnemonic::ADDC, {oR(m), oR(n)});
			break;
		case 0xF:
			S(i, Mnemonic::ADDV, {oR(m), oR(n)});
			break;
		}
	}

	/* ── Group 4: 0100nnnnmmmmdddd ───────────────────────────────────── */
	/* Dispatch primarily on lo = raw & 0xFF, with fallback on d nibble.  */

	static void g4(SH4Instruction& i, uint16_t raw, uint32_t n, uint32_t m, uint32_t d)
	{
		uint32_t lo = raw & 0xFF;

		switch (lo)
		{
		/* shifts / rotates */
		case 0x00:
			S(i, Mnemonic::SHLL, {oR(n)});
			return;
		case 0x01:
			S(i, Mnemonic::SHLR, {oR(n)});
			return;
		case 0x04:
			S(i, Mnemonic::ROTL, {oR(n)});
			return;
		case 0x05:
			S(i, Mnemonic::ROTR, {oR(n)});
			return;
		case 0x08:
			S(i, Mnemonic::SHLL2, {oR(n)});
			return;
		case 0x09:
			S(i, Mnemonic::SHLR2, {oR(n)});
			return;
		case 0x10:
			S(i, Mnemonic::DT, {oR(n)});
			return;
		case 0x11:
			S(i, Mnemonic::CMP_PZ, {oR(n)});
			return;
		case 0x15:
			S(i, Mnemonic::CMP_PL, {oR(n)});
			return;
		case 0x18:
			S(i, Mnemonic::SHLL8, {oR(n)});
			return;
		case 0x19:
			S(i, Mnemonic::SHLR8, {oR(n)});
			return;
		case 0x20:
			S(i, Mnemonic::SHAL, {oR(n)});
			return;
		case 0x21:
			S(i, Mnemonic::SHAR, {oR(n)});
			return;
		case 0x24:
			S(i, Mnemonic::ROTCL, {oR(n)});
			return;
		case 0x25:
			S(i, Mnemonic::ROTCR, {oR(n)});
			return;
		case 0x28:
			S(i, Mnemonic::SHLL16, {oR(n)});
			return;
		case 0x29:
			S(i, Mnemonic::SHLR16, {oR(n)});
			return;

		/* STS.L  sys, @-Rn */
		case 0x02:
			S(i, Mnemonic::STS_L, {oSR(REG_MACH), oATM(n)});
			return;
		case 0x12:
			S(i, Mnemonic::STS_L, {oSR(REG_MACL), oATM(n)});
			return;
		case 0x22:
			S(i, Mnemonic::STS_L, {oSR(REG_PR), oATM(n)});
			return;
		case 0x52:
			S(i, Mnemonic::STS_L, {oSR(REG_FPUL), oATM(n)});
			return;
		case 0x62:
			S(i, Mnemonic::STS_L, {oSR(REG_FPSCR), oATM(n)});
			return;

		/* STC.L  ctrl, @-Rn */
		case 0x03:
			S(i, Mnemonic::STC_L, {oCR(REG_SR), oATM(n)});
			return;
		case 0x13:
			S(i, Mnemonic::STC_L, {oCR(REG_GBR), oATM(n)});
			return;
		case 0x23:
			S(i, Mnemonic::STC_L, {oCR(REG_VBR), oATM(n)});
			return;
		case 0x33:
			S(i, Mnemonic::STC_L, {oCR(REG_SSR), oATM(n)});
			return;
		case 0x43:
			S(i, Mnemonic::STC_L, {oCR(REG_SPC), oATM(n)});
			return;
		case 0x32:
			S(i, Mnemonic::STC_L, {oCR(REG_SGR), oATM(n)});
			return;
		case 0xF2:
			S(i, Mnemonic::STC_L, {oCR(REG_DBR), oATM(n)});
			return;

		/* LDS.L  @Rn+, sys */
		case 0x06:
			S(i, Mnemonic::LDS_L, {oATP(n), oSR(REG_MACH)});
			return;
		case 0x16:
			S(i, Mnemonic::LDS_L, {oATP(n), oSR(REG_MACL)});
			return;
		case 0x26:
			S(i, Mnemonic::LDS_L, {oATP(n), oSR(REG_PR)});
			return;
		case 0x56:
			S(i, Mnemonic::LDS_L, {oATP(n), oSR(REG_FPUL)});
			return;
		case 0x66:
			S(i, Mnemonic::LDS_L, {oATP(n), oSR(REG_FPSCR)});
			return;

		/* LDC.L  @Rn+, ctrl */
		case 0x07:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_SR)});
			return;
		case 0x17:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_GBR)});
			return;
		case 0x27:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_VBR)});
			return;
		case 0x37:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_SSR)});
			return;
		case 0x47:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_SPC)});
			return;
		case 0x36:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_SGR)});
			return;
		case 0xF6:
			S(i, Mnemonic::LDC_L, {oATP(n), oCR(REG_DBR)});
			return;

		/* LDS  Rn, sys */
		case 0x0A:
			S(i, Mnemonic::LDS, {oR(n), oSR(REG_MACH)});
			return;
		case 0x1A:
			S(i, Mnemonic::LDS, {oR(n), oSR(REG_MACL)});
			return;
		case 0x2A:
			S(i, Mnemonic::LDS, {oR(n), oSR(REG_PR)});
			return;
		case 0x5A:
			S(i, Mnemonic::LDS, {oR(n), oSR(REG_FPUL)});
			return;
		case 0x6A:
			S(i, Mnemonic::LDS, {oR(n), oSR(REG_FPSCR)});
			return;

		/* LDC  Rn, ctrl */
		case 0x0E:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_SR)});
			return;
		case 0x1E:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_GBR)});
			return;
		case 0x2E:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_VBR)});
			return;
		case 0x3E:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_SSR)});
			return;
		case 0x4E:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_SPC)});
			return;
		case 0x3A:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_SGR)});
			return;
		case 0xFA:
			S(i, Mnemonic::LDC, {oR(n), oCR(REG_DBR)});
			return;

		/* branch / misc */
		case 0x0B:
			S(i, Mnemonic::JSR, {oAT(n)}, BranchKind::CALL_INDIRECT, true);
			return;
		case 0x2B:
			S(i, Mnemonic::JMP, {oAT(n)}, BranchKind::UNCOND_INDIRECT, true);
			return;
		case 0x1B:
			S(i, Mnemonic::TAS_B, {oAT(n)});
			return;
		case 0x14: /* invalid */
			return;
		}

		/* d-nibble based dispatch (catches all lo values not handled above) */
		switch (d)
		{
		case 0xC:
			S(i, Mnemonic::SHAD, {oR(m), oR(n)});
			return;
		case 0xD:
			S(i, Mnemonic::SHLD, {oR(m), oR(n)});
			return;
		case 0xF:
			S(i, Mnemonic::MAC_W, {oATP(m), oATP(n)});
			return;
		}

		/* Banked STC.L / LDC.L / LDC with m >= 8 */
		if (m >= 8)
		{
			uint32_t lo4 = lo & 0x0F;
			if (lo4 == 0x03)
				S(i, Mnemonic::STC_L, {oBANK(m), oATM(n)});
			else if (lo4 == 0x07)
				S(i, Mnemonic::LDC_L, {oATP(n), oBANK(m)});
			else if (lo4 == 0x0E)
				S(i, Mnemonic::LDC, {oR(n), oBANK(m)});
		}
	}

	/* ── Group 6: 0110nnnnmmmmdddd ───────────────────────────────────── */

	static void g6(SH4Instruction& i, uint32_t n, uint32_t m, uint32_t d)
	{
		switch (d)
		{
		case 0x0:
			S(i, Mnemonic::MOV_B, {oAT(m), oR(n)});
			break;
		case 0x1:
			S(i, Mnemonic::MOV_W, {oAT(m), oR(n)});
			break;
		case 0x2:
			S(i, Mnemonic::MOV_L, {oAT(m), oR(n)});
			break;
		case 0x3:
			S(i, Mnemonic::MOV, {oR(m), oR(n)});
			break;
		case 0x4:
			S(i, Mnemonic::MOV_B, {oATP(m), oR(n)});
			break;
		case 0x5:
			S(i, Mnemonic::MOV_W, {oATP(m), oR(n)});
			break;
		case 0x6:
			S(i, Mnemonic::MOV_L, {oATP(m), oR(n)});
			break;
		case 0x7:
			S(i, Mnemonic::NOT, {oR(m), oR(n)});
			break;
		case 0x8:
			S(i, Mnemonic::SWAP_B, {oR(m), oR(n)});
			break;
		case 0x9:
			S(i, Mnemonic::SWAP_W, {oR(m), oR(n)});
			break;
		case 0xA:
			S(i, Mnemonic::NEGC, {oR(m), oR(n)});
			break;
		case 0xB:
			S(i, Mnemonic::NEG, {oR(m), oR(n)});
			break;
		case 0xC:
			S(i, Mnemonic::EXTU_B, {oR(m), oR(n)});
			break;
		case 0xD:
			S(i, Mnemonic::EXTU_W, {oR(m), oR(n)});
			break;
		case 0xE:
			S(i, Mnemonic::EXTS_B, {oR(m), oR(n)});
			break;
		case 0xF:
			S(i, Mnemonic::EXTS_W, {oR(m), oR(n)});
			break;
		}
	}

	/* ── Group 8: 1000ooooRRRRdddd / 1000oooodddddddd ───────────────── */

	static void g8(SH4Instruction& i, uint16_t raw, uint32_t addr)
	{
		uint32_t op = (raw >> 8) & 0xF;
		uint32_t rn_g8 = (raw >> 4) & 0xF; /* register field for disp-based ops */
		uint32_t d4 = raw & 0xF;
		uint32_t d8 = raw & 0xFF;

		switch (op)
		{
		case 0x0:
			S(i, Mnemonic::MOV_B, {oR(0), oDREG(rn_g8, d4)});
			break;
		case 0x1:
			S(i, Mnemonic::MOV_W, {oR(0), oDREG(rn_g8, d4 * 2)});
			break;
		case 0x4:
			S(i, Mnemonic::MOV_B, {oDREG(rn_g8, d4), oR(0)});
			break;
		case 0x5:
			S(i, Mnemonic::MOV_W, {oDREG(rn_g8, d4 * 2), oR(0)});
			break;
		case 0x8:
			S(i, Mnemonic::CMP_EQ, {oI(se8(d8)), oR(0)});
			break;
		case 0x9:
		{
			uint32_t tgt = addr + 4 + se8(d8) * 2;
			ST(i, Mnemonic::BT, {oADDR(tgt)}, BranchKind::COND_TRUE, false, tgt);
			break;
		}
		case 0xB:
		{
			uint32_t tgt = addr + 4 + se8(d8) * 2;
			ST(i, Mnemonic::BF, {oADDR(tgt)}, BranchKind::COND_FALSE, false, tgt);
			break;
		}
		case 0xD:
		{
			uint32_t tgt = addr + 4 + se8(d8) * 2;
			ST(i, Mnemonic::BT_S, {oADDR(tgt)}, BranchKind::COND_TRUE, true, tgt);
			break;
		}
		case 0xF:
		{
			uint32_t tgt = addr + 4 + se8(d8) * 2;
			ST(i, Mnemonic::BF_S, {oADDR(tgt)}, BranchKind::COND_FALSE, true, tgt);
			break;
		}
		}
	}

	/* ── Group C: 1100ooooiiiiiiii ────────────────────────────────────── */

	static void gC(SH4Instruction& i, uint16_t raw, uint32_t addr)
	{
		uint32_t op = (raw >> 8) & 0xF;
		uint32_t imm = raw & 0xFF;

		switch (op)
		{
		case 0x0:
			S(i, Mnemonic::MOV_B, {oR(0), oDGBR(imm)});
			break;
		case 0x1:
			S(i, Mnemonic::MOV_W, {oR(0), oDGBR(imm * 2)});
			break;
		case 0x2:
			S(i, Mnemonic::MOV_L, {oR(0), oDGBR(imm * 4)});
			break;
		case 0x3:
			S(i, Mnemonic::TRAPA, {oI(imm)}, BranchKind::SYSCALL);
			break;
		case 0x4:
			S(i, Mnemonic::MOV_B, {oDGBR(imm), oR(0)});
			break;
		case 0x5:
			S(i, Mnemonic::MOV_W, {oDGBR(imm * 2), oR(0)});
			break;
		case 0x6:
			S(i, Mnemonic::MOV_L, {oDGBR(imm * 4), oR(0)});
			break;
		case 0x7:
		{
			uint32_t tgt = (addr & ~3u) + 4 + imm * 4;
			S(i, Mnemonic::MOVA, {oADDR(tgt), oR(0)});
			break;
		}
		case 0x8:
			S(i, Mnemonic::TST, {oI(imm), oR(0)});
			break;
		case 0x9:
			S(i, Mnemonic::AND, {oI(imm), oR(0)});
			break;
		case 0xA:
			S(i, Mnemonic::XOR, {oI(imm), oR(0)});
			break;
		case 0xB:
			S(i, Mnemonic::OR, {oI(imm), oR(0)});
			break;
		case 0xC:
			S(i, Mnemonic::TST_B, {oI(imm), oR0GBR()});
			break;
		case 0xD:
			S(i, Mnemonic::AND_B, {oI(imm), oR0GBR()});
			break;
		case 0xE:
			S(i, Mnemonic::XOR_B, {oI(imm), oR0GBR()});
			break;
		case 0xF:
			S(i, Mnemonic::OR_B, {oI(imm), oR0GBR()});
			break;
		}
	}

	/* ── Group F: 1111nnnnmmmmdddd  (FPU) ────────────────────────────── */

	static void gF(SH4Instruction& i, uint16_t raw, uint32_t n, uint32_t m, uint32_t d)
	{
		switch (d)
		{
		case 0x0:
			S(i, Mnemonic::FADD, {oFR(m), oFR(n)});
			break;
		case 0x1:
			S(i, Mnemonic::FSUB, {oFR(m), oFR(n)});
			break;
		case 0x2:
			S(i, Mnemonic::FMUL, {oFR(m), oFR(n)});
			break;
		case 0x3:
			S(i, Mnemonic::FDIV, {oFR(m), oFR(n)});
			break;
		case 0x4:
			S(i, Mnemonic::FCMP_EQ, {oFR(m), oFR(n)});
			break;
		case 0x5:
			S(i, Mnemonic::FCMP_GT, {oFR(m), oFR(n)});
			break;
		case 0x6:
			S(i, Mnemonic::FMOV, {oAR0(m), oFR(n)});
			break; /* @(R0,Rm),FRn */
		case 0x7:
			S(i, Mnemonic::FMOV, {oFR(m), oAR0(n)});
			break; /* FRm,@(R0,Rn) */
		case 0x8:
			S(i, Mnemonic::FMOV, {oAT(m), oFR(n)});
			break; /* @Rm,FRn      */
		case 0x9:
			S(i, Mnemonic::FMOV, {oATP(m), oFR(n)});
			break; /* @Rm+,FRn     */
		case 0xA:
			S(i, Mnemonic::FMOV, {oFR(m), oAT(n)});
			break; /* FRm,@Rn      */
		case 0xB:
			S(i, Mnemonic::FMOV, {oFR(m), oATM(n)});
			break; /* FRm,@-Rn     */
		case 0xC:
			S(i, Mnemonic::FMOV, {oFR(m), oFR(n)});
			break; /* FRm,FRn      */
		case 0xE:
			S(i, Mnemonic::FMAC, {oFR(0), oFR(m), oFR(n)});
			break;
		case 0xD:
		{
			/* Single-operand FPU: sub-dispatch on m nibble */
			uint32_t lo = (raw >> 4) & 0xF;
			switch (lo)
			{
			case 0x0:
				S(i, Mnemonic::FSTS, {oSR(REG_FPUL), oFR(n)});
				break;
			case 0x1:
				S(i, Mnemonic::FLDS, {oFR(n), oSR(REG_FPUL)});
				break;
			case 0x2:
				S(i, Mnemonic::FLOAT_OP, {oSR(REG_FPUL), oFR(n)});
				break;
			case 0x3:
				S(i, Mnemonic::FTRC, {oFR(n), oSR(REG_FPUL)});
				break;
			case 0x4:
				S(i, Mnemonic::FNEG, {oFR(n)});
				break;
			case 0x5:
				S(i, Mnemonic::FABS, {oFR(n)});
				break;
			case 0x6:
				S(i, Mnemonic::FSQRT, {oFR(n)});
				break;
			case 0x7:
				S(i, Mnemonic::FSRRA, {oFR(n)});
				break;
			case 0x8:
				S(i, Mnemonic::FLDI0, {oFR(n)});
				break;
			case 0x9:
				S(i, Mnemonic::FLDI1, {oFR(n)});
				break;
			case 0xA:
				S(i, Mnemonic::FCNVSD, {oSR(REG_FPUL), oDR(n)});
				break;
			case 0xB:
				S(i, Mnemonic::FCNVDS, {oDR(n), oSR(REG_FPUL)});
				break;
			case 0xD:
				S(i, Mnemonic::FSCA, {oSR(REG_FPUL), oDR(n)});
				break;
			case 0xE:
				S(i, Mnemonic::FIPR, {oFV(m & 0xC), oFV(n & 0xC)});
				break;
			case 0xF:
				if (n == 3)
					S(i, Mnemonic::FSCHG, {});
				else if (n == 0xB)
					S(i, Mnemonic::FRCHG, {});
				else if (n & 1)
					S(i, Mnemonic::FTRV, {oFV(n & 0xC)});
				break;
			}
			break;
		}
		}
	}

}  // anonymous namespace


/* ═════════════════════════════════════════════════════════════════════
 *  Public API
 * ═════════════════════════════════════════════════════════════════════ */

bool sh4_decode(const uint8_t* data, size_t len, uint32_t addr, SH4Instruction& out)
{
	if (len < 2)
		return false;

	uint16_t raw = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
	uint32_t top = (raw >> 12) & 0xF;
	uint32_t n = (raw >> 8) & 0xF;
	uint32_t m = (raw >> 4) & 0xF;
	uint32_t d = raw & 0xF;

	/* Default: .word  #raw */
	out = {};
	out.raw = raw;
	out.addr = addr;
	out.ops[0] = oI(static_cast<int32_t>(raw));
	out.op_count = 1;

	switch (top)
	{
	case 0x0:
		g0(out, raw, n, m, d);
		break;
	case 0x1:
		S(out, Mnemonic::MOV_L, {oR(m), oDREG(n, d * 4)});
		break;
	case 0x2:
		g2(out, n, m, d);
		break;
	case 0x3:
		g3(out, n, m, d);
		break;
	case 0x4:
		g4(out, raw, n, m, d);
		break;
	case 0x5:
		S(out, Mnemonic::MOV_L, {oDREG(m, d * 4), oR(n)});
		break;
	case 0x6:
		g6(out, n, m, d);
		break;
	case 0x7:
		S(out, Mnemonic::ADD, {oI(se8(raw & 0xFF)), oR(n)});
		break;
	case 0x8:
		g8(out, raw, addr);
		break;
	case 0x9:
	{
		uint32_t d8 = raw & 0xFF;
		uint32_t tgt = addr + 4 + d8 * 2;
		S(out, Mnemonic::MOV_W, {oDPC(tgt), oR(n)});
		break;
	}
	case 0xA:
	{
		int32_t d12 = se12(raw & 0xFFF);
		uint32_t tgt = addr + 4 + d12 * 2;
		ST(out, Mnemonic::BRA, {oADDR(tgt)}, BranchKind::UNCOND_DIRECT, true, tgt);
		break;
	}
	case 0xB:
	{
		int32_t d12 = se12(raw & 0xFFF);
		uint32_t tgt = addr + 4 + d12 * 2;
		ST(out, Mnemonic::BSR, {oADDR(tgt)}, BranchKind::CALL_DIRECT, true, tgt);
		break;
	}
	case 0xC:
		gC(out, raw, addr);
		break;
	case 0xD:
	{
		uint32_t d8 = raw & 0xFF;
		uint32_t tgt = (addr & ~3u) + 4 + d8 * 4;
		S(out, Mnemonic::MOV_L, {oDPC(tgt), oR(n)});
		break;
	}
	case 0xE:
		S(out, Mnemonic::MOV, {oI(se8(raw & 0xFF)), oR(n)});
		break;
	case 0xF:
		gF(out, raw, n, m, d);
		break;
	}

	return true;
}


/* ═════════════════════════════════════════════════════════════════════
 *  Mnemonic → string table
 * ═════════════════════════════════════════════════════════════════════ */

const char* sh4_mnemonic_name(Mnemonic mn)
{
	switch (mn)
	{
	case Mnemonic::UNKNOWN:
		return ".word";
	/* data movement */
	case Mnemonic::MOV:
		return "mov";
	case Mnemonic::MOV_B:
		return "mov.b";
	case Mnemonic::MOV_W:
		return "mov.w";
	case Mnemonic::MOV_L:
		return "mov.l";
	case Mnemonic::MOVA:
		return "mova";
	case Mnemonic::MOVT:
		return "movt";
	case Mnemonic::MOVCA_L:
		return "movca.l";
	/* arithmetic */
	case Mnemonic::ADD:
		return "add";
	case Mnemonic::ADDC:
		return "addc";
	case Mnemonic::ADDV:
		return "addv";
	case Mnemonic::SUB:
		return "sub";
	case Mnemonic::SUBC:
		return "subc";
	case Mnemonic::SUBV:
		return "subv";
	case Mnemonic::NEG:
		return "neg";
	case Mnemonic::NEGC:
		return "negc";
	case Mnemonic::DT:
		return "dt";
	case Mnemonic::MUL_L:
		return "mul.l";
	case Mnemonic::MULS_W:
		return "muls.w";
	case Mnemonic::MULU_W:
		return "mulu.w";
	case Mnemonic::DMULS_L:
		return "dmuls.l";
	case Mnemonic::DMULU_L:
		return "dmulu.l";
	case Mnemonic::MAC_L:
		return "mac.l";
	case Mnemonic::MAC_W:
		return "mac.w";
	/* compare */
	case Mnemonic::CMP_EQ:
		return "cmp/eq";
	case Mnemonic::CMP_GE:
		return "cmp/ge";
	case Mnemonic::CMP_GT:
		return "cmp/gt";
	case Mnemonic::CMP_HS:
		return "cmp/hs";
	case Mnemonic::CMP_HI:
		return "cmp/hi";
	case Mnemonic::CMP_PL:
		return "cmp/pl";
	case Mnemonic::CMP_PZ:
		return "cmp/pz";
	case Mnemonic::CMP_STR:
		return "cmp/str";
	case Mnemonic::TST:
		return "tst";
	case Mnemonic::TST_B:
		return "tst.b";
	/* logic */
	case Mnemonic::AND:
		return "and";
	case Mnemonic::OR:
		return "or";
	case Mnemonic::XOR:
		return "xor";
	case Mnemonic::NOT:
		return "not";
	case Mnemonic::AND_B:
		return "and.b";
	case Mnemonic::OR_B:
		return "or.b";
	case Mnemonic::XOR_B:
		return "xor.b";
	/* shifts */
	case Mnemonic::SHLL:
		return "shll";
	case Mnemonic::SHLR:
		return "shlr";
	case Mnemonic::SHAL:
		return "shal";
	case Mnemonic::SHAR:
		return "shar";
	case Mnemonic::SHLL2:
		return "shll2";
	case Mnemonic::SHLL8:
		return "shll8";
	case Mnemonic::SHLL16:
		return "shll16";
	case Mnemonic::SHLR2:
		return "shlr2";
	case Mnemonic::SHLR8:
		return "shlr8";
	case Mnemonic::SHLR16:
		return "shlr16";
	case Mnemonic::SHAD:
		return "shad";
	case Mnemonic::SHLD:
		return "shld";
	/* rotates */
	case Mnemonic::ROTL:
		return "rotl";
	case Mnemonic::ROTR:
		return "rotr";
	case Mnemonic::ROTCL:
		return "rotcl";
	case Mnemonic::ROTCR:
		return "rotcr";
	/* extension / swap */
	case Mnemonic::EXTU_B:
		return "extu.b";
	case Mnemonic::EXTU_W:
		return "extu.w";
	case Mnemonic::EXTS_B:
		return "exts.b";
	case Mnemonic::EXTS_W:
		return "exts.w";
	case Mnemonic::SWAP_B:
		return "swap.b";
	case Mnemonic::SWAP_W:
		return "swap.w";
	case Mnemonic::XTRCT:
		return "xtrct";
	/* branch / control */
	case Mnemonic::BRA:
		return "bra";
	case Mnemonic::BSR:
		return "bsr";
	case Mnemonic::BT:
		return "bt";
	case Mnemonic::BF:
		return "bf";
	case Mnemonic::BT_S:
		return "bt/s";
	case Mnemonic::BF_S:
		return "bf/s";
	case Mnemonic::JMP:
		return "jmp";
	case Mnemonic::JSR:
		return "jsr";
	case Mnemonic::BRAF:
		return "braf";
	case Mnemonic::BSRF:
		return "bsrf";
	case Mnemonic::RTS:
		return "rts";
	case Mnemonic::RTE:
		return "rte";
	case Mnemonic::TRAPA:
		return "trapa";
	/* system register transfer */
	case Mnemonic::STS:
		return "sts";
	case Mnemonic::STS_L:
		return "sts.l";
	case Mnemonic::LDS:
		return "lds";
	case Mnemonic::LDS_L:
		return "lds.l";
	case Mnemonic::STC:
		return "stc";
	case Mnemonic::STC_L:
		return "stc.l";
	case Mnemonic::LDC:
		return "ldc";
	case Mnemonic::LDC_L:
		return "ldc.l";
	/* division */
	case Mnemonic::DIV0S:
		return "div0s";
	case Mnemonic::DIV0U:
		return "div0u";
	case Mnemonic::DIV1:
		return "div1";
	/* misc */
	case Mnemonic::CLRT:
		return "clrt";
	case Mnemonic::SETT:
		return "sett";
	case Mnemonic::CLRMAC:
		return "clrmac";
	case Mnemonic::CLRS:
		return "clrs";
	case Mnemonic::SETS:
		return "sets";
	case Mnemonic::TAS_B:
		return "tas.b";
	/* FPU */
	case Mnemonic::FMOV:
		return "fmov";
	case Mnemonic::FMOV_S:
		return "fmov.s";
	case Mnemonic::FMOV_D:
		return "fmov.d";
	case Mnemonic::FADD:
		return "fadd";
	case Mnemonic::FSUB:
		return "fsub";
	case Mnemonic::FMUL:
		return "fmul";
	case Mnemonic::FDIV:
		return "fdiv";
	case Mnemonic::FSQRT:
		return "fsqrt";
	case Mnemonic::FABS:
		return "fabs";
	case Mnemonic::FNEG:
		return "fneg";
	case Mnemonic::FLOAT_OP:
		return "float";
	case Mnemonic::FTRC:
		return "ftrc";
	case Mnemonic::FCMP_EQ:
		return "fcmp/eq";
	case Mnemonic::FCMP_GT:
		return "fcmp/gt";
	case Mnemonic::FLDS:
		return "flds";
	case Mnemonic::FSTS:
		return "fsts";
	case Mnemonic::FSCHG:
		return "fschg";
	case Mnemonic::FRCHG:
		return "frchg";
	case Mnemonic::FLDI0:
		return "fldi0";
	case Mnemonic::FLDI1:
		return "fldi1";
	case Mnemonic::FMAC:
		return "fmac";
	case Mnemonic::FCNVSD:
		return "fcnvsd";
	case Mnemonic::FCNVDS:
		return "fcnvds";
	/* NOP-like */
	case Mnemonic::NOP:
		return "nop";
	case Mnemonic::PREF:
		return "pref";
	case Mnemonic::OCBI:
		return "ocbi";
	case Mnemonic::OCBP:
		return "ocbp";
	case Mnemonic::OCBWB:
		return "ocbwb";
	case Mnemonic::LDTLB:
		return "ldtlb";
	/* unimplemented */
	case Mnemonic::FIPR:
		return "fipr";
	case Mnemonic::FTRV:
		return "ftrv";
	case Mnemonic::FSRRA:
		return "fsrra";
	case Mnemonic::FSCA:
		return "fsca";
	case Mnemonic::SLEEP:
		return "sleep";
	/* raw */
	case Mnemonic::DOT_WORD:
		return ".word";

	case Mnemonic::MNEMONIC_COUNT:
		break;
	}
	return ".word";
}
