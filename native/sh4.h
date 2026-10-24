#pragma once
/*  SuperBiHnja native SH-4 architecture plugin — shared definitions.
 *
 *  SH-4 (SH7750 family), little-endian, 32-bit, fixed 16-bit instruction
 *  encoding.  Delay-slot branches use BN native delay-slot support.
 */

#include <cstdint>
#include <cstddef>

/* ── Register IDs ─────────────────────────────────────────────────── */

enum SH4Reg : uint32_t
{
	REG_R0 = 0,
	REG_R1,
	REG_R2,
	REG_R3,
	REG_R4,
	REG_R5,
	REG_R6,
	REG_R7,
	REG_R8,
	REG_R9,
	REG_R10,
	REG_R11,
	REG_R12,
	REG_R13,
	REG_R14,
	REG_R15,
	REG_R0_BANK,
	REG_R1_BANK,
	REG_R2_BANK,
	REG_R3_BANK,
	REG_R4_BANK,
	REG_R5_BANK,
	REG_R6_BANK,
	REG_R7_BANK,
	/* control */
	REG_SR,
	REG_GBR,
	REG_VBR,
	REG_SSR,
	REG_SPC,
	REG_SGR,
	REG_DBR,
	/* system */
	REG_MACH,
	REG_MACL,
	REG_PR,
	/* program counter */
	REG_PC,
	/* FPU control */
	REG_FPSCR,
	REG_FPUL,
	/* single-precision  fr0..fr15 */
	REG_FR0,
	REG_FR1,
	REG_FR2,
	REG_FR3,
	REG_FR4,
	REG_FR5,
	REG_FR6,
	REG_FR7,
	REG_FR8,
	REG_FR9,
	REG_FR10,
	REG_FR11,
	REG_FR12,
	REG_FR13,
	REG_FR14,
	REG_FR15,
	/* extended bank   xf0..xf15 */
	REG_XF0,
	REG_XF1,
	REG_XF2,
	REG_XF3,
	REG_XF4,
	REG_XF5,
	REG_XF6,
	REG_XF7,
	REG_XF8,
	REG_XF9,
	REG_XF10,
	REG_XF11,
	REG_XF12,
	REG_XF13,
	REG_XF14,
	REG_XF15,
	/* double-precision  dr0,dr2,...,dr14 */
	REG_DR0,
	REG_DR2,
	REG_DR4,
	REG_DR6,
	REG_DR8,
	REG_DR10,
	REG_DR12,
	REG_DR14,
	/* extended doubles  xd0,xd2,...,xd14 */
	REG_XD0,
	REG_XD2,
	REG_XD4,
	REG_XD6,
	REG_XD8,
	REG_XD10,
	REG_XD12,
	REG_XD14,
	/* float vectors  fv0,fv4,fv8,fv12 */
	REG_FV0,
	REG_FV4,
	REG_FV8,
	REG_FV12,
	REG_COUNT
};

enum SH4Intrinsic : uint32_t
{
	INTRINSIC_FSCA = 0,  // __fsca(fpul) -> (sin, cos)
	INTRINSIC_SLEEP,     // __sleep()
	INTRINSIC_COUNT
};

/* ── Flag IDs ─────────────────────────────────────────────────────── */

enum SH4Flag : uint32_t
{
	FLAG_T = 0,
	FLAG_S,
	FLAG_Q,
	FLAG_M,
	FLAG_COUNT
};

/* ── Operand types ────────────────────────────────────────────────── */

enum class OpType : uint8_t
{
	NONE = 0,
	REG,         /* Rn                           */
	CTRL_REG,    /* SR / GBR / VBR / …           */
	SYS_REG,     /* MACH / MACL / PR              */
	FR_REG,      /* FRn                           */
	DR_REG,      /* DRn                           */
	XD_REG,      /* XDn                           */
	FV_REG,      /* FVn                           */
	XF_REG,      /* XFn                           */
	IMM,         /* #imm                          */
	DISP,        /* raw displacement (unused?)     */
	AT_REG,      /* @Rn                           */
	AT_REG_POST, /* @Rn+                          */
	AT_PRE_REG,  /* @-Rn                          */
	DISP_REG,    /* @(disp,Rn)                    */
	DISP_PC,     /* @(disp,PC)  — resolved to abs */
	DISP_GBR,    /* @(disp,GBR)                   */
	AT_R0_REG,   /* @(R0,Rn)                      */
	AT_R0_GBR,   /* @(R0,GBR)                     */
	ADDR,        /* absolute / branch target       */
};

inline bool is_mem_type(OpType t)
{
	switch (t)
	{
	case OpType::AT_REG:
	case OpType::AT_REG_POST:
	case OpType::AT_PRE_REG:
	case OpType::DISP_REG:
	case OpType::DISP_PC:
	case OpType::DISP_GBR:
	case OpType::AT_R0_REG:
	case OpType::AT_R0_GBR:
		return true;
	default:
		return false;
	}
}

/* ── Branch classification ────────────────────────────────────────── */

enum class BranchKind : uint8_t
{
	NONE = 0,
	UNCOND_DIRECT,
	UNCOND_INDIRECT,
	COND_TRUE,        /* BT / BT/S */
	COND_FALSE,       /* BF / BF/S */
	CALL_DIRECT,      /* BSR       */
	CALL_INDIRECT,    /* JSR @Rn   */
	CALL_REG_DIRECT,  /* BSRF Rn   */
	RETURN,           /* RTS       */
	EXCEPTION_RETURN, /* RTE       */
	SYSCALL,          /* TRAPA     */
};

/* ── Mnemonic enum  ───────────────────────────────────────────────── */
/*    Avoids string dispatch in lifter; decoder sets this directly.     */

enum class Mnemonic : uint16_t
{
	UNKNOWN = 0,
	/* data movement */
	MOV,
	MOV_B,
	MOV_W,
	MOV_L,
	MOVA,
	MOVT,
	MOVCA_L,
	/* arithmetic */
	ADD,
	ADDC,
	ADDV,
	SUB,
	SUBC,
	SUBV,
	NEG,
	NEGC,
	DT,
	MUL_L,
	MULS_W,
	MULU_W,
	DMULS_L,
	DMULU_L,
	MAC_L,
	MAC_W,
	/* compare — set T */
	CMP_EQ,
	CMP_GE,
	CMP_GT,
	CMP_HS,
	CMP_HI,
	CMP_PL,
	CMP_PZ,
	CMP_STR,
	TST,
	TST_B,
	/* logic */
	AND,
	OR,
	XOR,
	NOT,
	AND_B,
	OR_B,
	XOR_B,
	/* shifts with T */
	SHLL,
	SHLR,
	SHAL,
	SHAR,
	/* shifts constant */
	SHLL2,
	SHLL8,
	SHLL16,
	SHLR2,
	SHLR8,
	SHLR16,
	/* dynamic shifts */
	SHAD,
	SHLD,
	/* rotates */
	ROTL,
	ROTR,
	ROTCL,
	ROTCR,
	/* extension / swap */
	EXTU_B,
	EXTU_W,
	EXTS_B,
	EXTS_W,
	SWAP_B,
	SWAP_W,
	XTRCT,
	/* branch / control */
	BRA,
	BSR,
	BT,
	BF,
	BT_S,
	BF_S,
	JMP,
	JSR,
	BRAF,
	BSRF,
	RTS,
	RTE,
	TRAPA,
	/* system register transfer */
	STS,
	STS_L,
	LDS,
	LDS_L,
	STC,
	STC_L,
	LDC,
	LDC_L,
	/* division */
	DIV0S,
	DIV0U,
	DIV1,
	/* misc */
	CLRT,
	SETT,
	CLRMAC,
	CLRS,
	SETS,
	TAS_B,
	/* FPU */
	FMOV,
	FMOV_S,
	FMOV_D,
	FADD,
	FSUB,
	FMUL,
	FDIV,
	FSQRT,
	FABS,
	FNEG,
	FLOAT_OP,
	FTRC,
	FCMP_EQ,
	FCMP_GT,
	FLDS,
	FSTS,
	FSCHG,
	FRCHG,
	FLDI0,
	FLDI1,
	FMAC,
	FCNVSD,
	FCNVDS,
	/* NOP-like */
	NOP,
	PREF,
	OCBI,
	OCBP,
	OCBWB,
	LDTLB,
	/* unimplemented */
	FIPR,
	FTRV,
	FSRRA,
	FSCA,
	SLEEP,
	/* raw / unknown */
	DOT_WORD,

	MNEMONIC_COUNT
};

/* ── Operand ──────────────────────────────────────────────────────── */

struct SH4Operand
{
	OpType type = OpType::NONE;
	SH4Reg reg = REG_R0;  /* primary register                    */
	SH4Reg base = REG_R0; /* base for DISP_REG / AT_R0_REG      */
	int32_t imm = 0;      /* immediate, displacement, or abs addr */
};

/* ── Decoded instruction ──────────────────────────────────────────── */

struct SH4Instruction
{
	Mnemonic mn = Mnemonic::DOT_WORD;
	uint16_t raw = 0;
	uint32_t addr = 0;
	SH4Operand ops[3];
	uint8_t op_count = 0;
	BranchKind branch = BranchKind::NONE;
	bool has_delay = false;
	bool has_target = false;
	uint32_t target = 0; /* resolved branch target */
};

/* ── Register metadata (name + size) ──────────────────────────────── */

struct RegMeta
{
	const char* name;
	size_t size; /* bytes: 4, 8, or 16 */
};

/* Defined in sh4_arch.cpp */
extern const RegMeta kRegMeta[REG_COUNT];

/* Maps string name → SH4Reg; returns REG_COUNT on miss. */
SH4Reg sh4_reg_by_name(const char* name);
