/*  SuperBiHnja — SH-4 Architecture plugin for Binary Ninja (native).
 *
 *  SH-4 (SH7750 family), little-endian, 32-bit, fixed 16-bit instruction
 *  encoding.  Delay-slot branches are consumed as 4-byte pairs.
 */

#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "sh4.h"

using namespace BinaryNinja;
using namespace std;

/* ── Decoder / lifter entry points (defined in sh4_decode.cpp / sh4_lift.cpp) */

extern bool sh4_decode(const uint8_t* data, size_t len, uint32_t addr, SH4Instruction& out);
extern const char* sh4_mnemonic_name(Mnemonic mn);
extern bool sh4_lift(Architecture* arch, const SH4Instruction& insn, LowLevelILFunction& il);

/* ══════════════════════════════════════════════════════════════════════
 *  Register metadata table
 * ══════════════════════════════════════════════════════════════════════ */

const RegMeta kRegMeta[REG_COUNT] = {
	/* REG_R0  .. REG_R15 — general-purpose, 4 bytes */
	{"r0", 4},
	{"r1", 4},
	{"r2", 4},
	{"r3", 4},
	{"r4", 4},
	{"r5", 4},
	{"r6", 4},
	{"r7", 4},
	{"r8", 4},
	{"r9", 4},
	{"r10", 4},
	{"r11", 4},
	{"r12", 4},
	{"r13", 4},
	{"r14", 4},
	{"r15", 4},

	/* REG_R0_BANK .. REG_R7_BANK — banked, 4 bytes */
	{"r0_bank", 4},
	{"r1_bank", 4},
	{"r2_bank", 4},
	{"r3_bank", 4},
	{"r4_bank", 4},
	{"r5_bank", 4},
	{"r6_bank", 4},
	{"r7_bank", 4},

	/* control regs — 4 bytes each */
	{"sr", 4},
	{"gbr", 4},
	{"vbr", 4},
	{"ssr", 4},
	{"spc", 4},
	{"sgr", 4},
	{"dbr", 4},

	/* system regs — 4 bytes each */
	{"mach", 4},
	{"macl", 4},
	{"pr", 4},

	/* program counter */
	{"pc", 4},

	/* FPU control */
	{"fpscr", 4},
	{"fpul", 4},

	/* single-precision  fr0..fr15 — 4 bytes */
	{"fr0", 4},
	{"fr1", 4},
	{"fr2", 4},
	{"fr3", 4},
	{"fr4", 4},
	{"fr5", 4},
	{"fr6", 4},
	{"fr7", 4},
	{"fr8", 4},
	{"fr9", 4},
	{"fr10", 4},
	{"fr11", 4},
	{"fr12", 4},
	{"fr13", 4},
	{"fr14", 4},
	{"fr15", 4},

	/* extended bank  xf0..xf15 — 4 bytes */
	{"xf0", 4},
	{"xf1", 4},
	{"xf2", 4},
	{"xf3", 4},
	{"xf4", 4},
	{"xf5", 4},
	{"xf6", 4},
	{"xf7", 4},
	{"xf8", 4},
	{"xf9", 4},
	{"xf10", 4},
	{"xf11", 4},
	{"xf12", 4},
	{"xf13", 4},
	{"xf14", 4},
	{"xf15", 4},

	/* double-precision  dr0,dr2,...,dr14 — 8 bytes */
	{"dr0", 8},
	{"dr2", 8},
	{"dr4", 8},
	{"dr6", 8},
	{"dr8", 8},
	{"dr10", 8},
	{"dr12", 8},
	{"dr14", 8},

	/* extended doubles  xd0,xd2,...,xd14 — 8 bytes */
	{"xd0", 8},
	{"xd2", 8},
	{"xd4", 8},
	{"xd6", 8},
	{"xd8", 8},
	{"xd10", 8},
	{"xd12", 8},
	{"xd14", 8},

	/* float vectors  fv0,fv4,fv8,fv12 — 16 bytes */
	{"fv0", 16},
	{"fv4", 16},
	{"fv8", 16},
	{"fv12", 16},
};

/* ── sh4_reg_by_name ─────────────────────────────────────────────── */

SH4Reg sh4_reg_by_name(const char* name)
{
	for (uint32_t i = 0; i < REG_COUNT; ++i)
		if (strcmp(kRegMeta[i].name, name) == 0)
			return static_cast<SH4Reg>(i);
	return REG_COUNT;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Flag helpers
 * ══════════════════════════════════════════════════════════════════════ */

static const char* kFlagNames[FLAG_COUNT] = {"T", "S", "Q", "M"};

/* Flag-write type IDs (1-based; 0 = no write) */
enum : uint32_t
{
	FWT_NONE = 0,
	FWT_WRITE_T = 1,   /* writes FLAG_T only                */
	FWT_WRITE_TQM = 2, /* writes FLAG_T, FLAG_Q, FLAG_M     */
};

/* Semantic flag class IDs */
enum : uint32_t
{
	SFC_CLASS_T = 0
};

/* Semantic flag group IDs */
enum : uint32_t
{
	SFG_GROUP_T = 0
};

/* ══════════════════════════════════════════════════════════════════════
 *  Text token helpers
 * ══════════════════════════════════════════════════════════════════════ */

static void tok_imm(vector<InstructionTextToken>& out, int32_t v)
{
	char buf[32];
	uint32_t uv = static_cast<uint32_t>(v);
	if (-128 <= v && v <= 255)
		snprintf(buf, sizeof(buf), "#0x%x", uv & 0xffu);
	else
		snprintf(buf, sizeof(buf), "#0x%x", uv);
	out.emplace_back(IntegerToken, buf, uv);
}

static void tok_addr(vector<InstructionTextToken>& out, uint32_t addr)
{
	char buf[16];
	snprintf(buf, sizeof(buf), "0x%x", addr);
	out.emplace_back(PossibleAddressToken, buf, addr);
}

static void tok_reg(vector<InstructionTextToken>& out, SH4Reg reg)
{
	out.emplace_back(RegisterToken, kRegMeta[reg].name);
}

static void tok_operand(const SH4Operand& op, vector<InstructionTextToken>& out)
{
	switch (op.type)
	{
	case OpType::REG:
	case OpType::CTRL_REG:
	case OpType::SYS_REG:
	case OpType::FR_REG:
	case OpType::DR_REG:
	case OpType::XD_REG:
	case OpType::FV_REG:
	case OpType::XF_REG:
		tok_reg(out, op.reg);
		break;

	case OpType::IMM:
		tok_imm(out, op.imm);
		break;

	case OpType::ADDR:
		tok_addr(out, static_cast<uint32_t>(op.imm));
		break;

	case OpType::DISP_PC:
		tok_addr(out, static_cast<uint32_t>(op.imm));
		break;

	case OpType::DISP_REG:
	{
		char buf[16];
		snprintf(buf, sizeof(buf), "0x%x", static_cast<uint32_t>(op.imm));
		out.emplace_back(BeginMemoryOperandToken, "@(");
		out.emplace_back(IntegerToken, buf, static_cast<uint64_t>(static_cast<uint32_t>(op.imm)));
		out.emplace_back(TextToken, ",");
		tok_reg(out, op.base);
		out.emplace_back(EndMemoryOperandToken, ")");
		break;
	}

	case OpType::DISP_GBR:
	{
		char buf[16];
		snprintf(buf, sizeof(buf), "0x%x", static_cast<uint32_t>(op.imm));
		out.emplace_back(BeginMemoryOperandToken, "@(");
		out.emplace_back(IntegerToken, buf, static_cast<uint64_t>(static_cast<uint32_t>(op.imm)));
		out.emplace_back(TextToken, ",");
		out.emplace_back(RegisterToken, "gbr");
		out.emplace_back(EndMemoryOperandToken, ")");
		break;
	}

	case OpType::AT_REG:
		out.emplace_back(BeginMemoryOperandToken, "@");
		tok_reg(out, op.reg);
		out.emplace_back(EndMemoryOperandToken, "");
		break;

	case OpType::AT_REG_POST:
		out.emplace_back(BeginMemoryOperandToken, "@");
		tok_reg(out, op.reg);
		out.emplace_back(EndMemoryOperandToken, "+");
		break;

	case OpType::AT_PRE_REG:
		out.emplace_back(BeginMemoryOperandToken, "@-");
		tok_reg(out, op.reg);
		out.emplace_back(EndMemoryOperandToken, "");
		break;

	case OpType::AT_R0_REG:
		out.emplace_back(BeginMemoryOperandToken, "@(");
		out.emplace_back(RegisterToken, "r0");
		out.emplace_back(TextToken, ",");
		tok_reg(out, op.base);
		out.emplace_back(EndMemoryOperandToken, ")");
		break;

	case OpType::AT_R0_GBR:
		out.emplace_back(BeginMemoryOperandToken, "@(");
		out.emplace_back(RegisterToken, "r0");
		out.emplace_back(TextToken, ",");
		out.emplace_back(RegisterToken, "gbr");
		out.emplace_back(EndMemoryOperandToken, ")");
		break;

	case OpType::DISP:
	{
		char buf[16];
		snprintf(buf, sizeof(buf), "0x%x", static_cast<uint32_t>(op.imm));
		out.emplace_back(IntegerToken, buf, static_cast<uint64_t>(static_cast<uint32_t>(op.imm)));
		break;
	}

	case OpType::NONE:
	default:
		break;
	}
}

/* ══════════════════════════════════════════════════════════════════════
 *  SH4Architecture
 * ══════════════════════════════════════════════════════════════════════ */

class SH4Architecture : public Architecture
{
public:
	SH4Architecture(const string& name) : Architecture(name) {}

	/* ── Core properties ──────────────────────────────────────────── */

	BNEndianness GetEndianness() const override { return LittleEndian; }
	size_t GetAddressSize() const override { return 4; }
	size_t GetDefaultIntegerSize() const override { return 4; }
	size_t GetInstructionAlignment() const override { return 2; }
	size_t GetMaxInstructionLength() const override { return 4; }
	size_t GetOpcodeDisplayLength() const override { return 2; }

	/* ── Registers ────────────────────────────────────────────────── */

	string GetRegisterName(uint32_t reg) override
	{
		if (reg < REG_COUNT)
			return kRegMeta[reg].name;
		return "";
	}

	BNRegisterInfo GetRegisterInfo(uint32_t reg) override
	{
		BNRegisterInfo ri;
		ri.fullWidthRegister = reg;
		ri.offset = 0;
		if (reg < REG_COUNT)
			ri.size = kRegMeta[reg].size;
		else
			ri.size = 4;
		ri.extend = NoExtend;
		return ri;
	}

	vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> regs;
		regs.reserve(REG_COUNT);
		for (uint32_t i = 0; i < REG_COUNT; ++i)
			regs.push_back(i);
		return regs;
	}

	vector<uint32_t> GetFullWidthRegisters() override { return GetAllRegisters(); }

	uint32_t GetStackPointerRegister() override { return REG_R15; }
	uint32_t GetLinkRegister() override { return REG_PR; }

	/* ── Flags ────────────────────────────────────────────────────── */

	string GetFlagName(uint32_t flag) override
	{
		if (flag < FLAG_COUNT)
			return kFlagNames[flag];
		return "";
	}

	vector<uint32_t> GetAllFlags() override { return {FLAG_T, FLAG_S, FLAG_Q, FLAG_M}; }

	BNFlagRole GetFlagRole(uint32_t flag, uint32_t /*semClass*/) override
	{
		(void)flag;
		return SpecialFlagRole;
	}

	vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t /*semClass*/) override
	{
		switch (cond)
		{
		case LLFC_E:
		case LLFC_NE:
		case LLFC_SLT:
		case LLFC_SGE:
			return {FLAG_T};
		default:
			return {};
		}
	}

	/* ── Flag write types ─────────────────────────────────────────── */

	string GetFlagWriteTypeName(uint32_t wt) override
	{
		switch (wt)
		{
		case FWT_WRITE_T:
			return "writeT";
		case FWT_WRITE_TQM:
			return "writeTQM";
		default:
			return "";
		}
	}

	vector<uint32_t> GetAllFlagWriteTypes() override { return {FWT_WRITE_T, FWT_WRITE_TQM}; }

	vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t wt) override
	{
		switch (wt)
		{
		case FWT_WRITE_T:
			return {FLAG_T};
		case FWT_WRITE_TQM:
			return {FLAG_T, FLAG_Q, FLAG_M};
		default:
			return {};
		}
	}

	/* ── Semantic flag classes & groups ────────────────────────────── */

	vector<uint32_t> GetAllSemanticFlagClasses() override { return {SFC_CLASS_T}; }

	string GetSemanticFlagClassName(uint32_t semClass) override
	{
		if (semClass == SFC_CLASS_T)
			return "classT";
		return "";
	}

	vector<uint32_t> GetAllSemanticFlagGroups() override { return {SFG_GROUP_T}; }

	string GetSemanticFlagGroupName(uint32_t semGroup) override
	{
		if (semGroup == SFG_GROUP_T)
			return "groupT";
		return "";
	}

	uint32_t GetSemanticClassForFlagWriteType(uint32_t /*wt*/) override { return SFC_CLASS_T; }

	vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t group) override
	{
		if (group == SFG_GROUP_T)
			return {FLAG_T};
		return {};
	}

	map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t group) override
	{
		if (group == SFG_GROUP_T)
			return {{SFC_CLASS_T, LLFC_E}};
		return {};
	}

	/* ── Flag condition IL ────────────────────────────────────────── */

	ExprId GetFlagConditionLowLevelIL(
		BNLowLevelILFlagCondition cond, uint32_t /*semClass*/, LowLevelILFunction& il) override
	{
		switch (cond)
		{
		case LLFC_E:
			/* T == 1 */
			return il.Flag(FLAG_T);
		case LLFC_NE:
			/* T == 0  →  NOT T */
			return il.Not(0, il.Flag(FLAG_T));
		default:
			return il.Unimplemented();
		}
	}

	ExprId GetSemanticFlagGroupLowLevelIL(uint32_t /*group*/, LowLevelILFunction& il) override
	{
		return il.Flag(FLAG_T);
	}

	/* ── Intrinsics ───────────────────────────────────────────────── */

	vector<uint32_t> GetAllIntrinsics() override { return {INTRINSIC_FSCA, INTRINSIC_SLEEP}; }

	string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case INTRINSIC_FSCA:
			return "__fsca";
		case INTRINSIC_SLEEP:
			return "__sleep";
		default:
			return "";
		}
	}

	vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case INTRINSIC_FSCA:
			return {NameAndType("angle", Type::IntegerType(4, false))};
		default:
			return {};
		}
	}

	vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case INTRINSIC_FSCA:
			return {Type::FloatType(4), Type::FloatType(4)};
		default:
			return {};
		}
	}

	/* ── GetInstructionInfo ───────────────────────────────────────── */

	bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
	{
		if (maxLen < 2)
			return false;

		SH4Instruction insn;
		if (!sh4_decode(data, maxLen, static_cast<uint32_t>(addr), insn))
			return false;

		result.length = 2;
		uint8_t ds = insn.has_delay ? 1 : 0;

		switch (insn.branch)
		{
		case BranchKind::NONE:
			break;

		case BranchKind::UNCOND_DIRECT:
			if (insn.has_target)
				result.AddBranch(UnconditionalBranch, insn.target, nullptr, ds);
			break;

		case BranchKind::UNCOND_INDIRECT:
			result.AddBranch(UnresolvedBranch, 0, nullptr, ds);
			break;

		case BranchKind::COND_TRUE:
			if (insn.has_target)
			{
				result.AddBranch(TrueBranch, insn.target, nullptr, ds);
				result.AddBranch(FalseBranch, addr + 2 + ds * 2, nullptr, ds);
			}
			break;

		case BranchKind::COND_FALSE:
			if (insn.has_target)
			{
				/* BF/BF.S: condition is "T == 0"; TrueBranch = target (taken),
				 * FalseBranch = fallthrough (not taken).  IL encodes polarity. */
				result.AddBranch(TrueBranch, insn.target, nullptr, ds);
				result.AddBranch(FalseBranch, addr + 2 + ds * 2, nullptr, ds);
			}
			break;

		case BranchKind::CALL_DIRECT:
			if (insn.has_target)
				result.AddBranch(CallDestination, insn.target, nullptr, ds);
			break;

		case BranchKind::CALL_INDIRECT:
			result.AddBranch(CallDestination, 0, nullptr, ds);
			break;

		case BranchKind::CALL_REG_DIRECT:
			result.AddBranch(CallDestination, 0, nullptr, ds);
			break;

		case BranchKind::RETURN:
		case BranchKind::EXCEPTION_RETURN:
			result.AddBranch(FunctionReturn, 0, nullptr, ds);
			break;

		case BranchKind::SYSCALL:
			result.AddBranch(SystemCall);
			break;
		}

		return true;
	}

	/* ── GetInstructionText ───────────────────────────────────────── */

	bool GetInstructionText(
		const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		if (len < 2)
			return false;

		SH4Instruction insn;
		if (!sh4_decode(data, len, static_cast<uint32_t>(addr), insn))
			return false;

		len = 2;

		/* Mnemonic */
		const char* mn_name = sh4_mnemonic_name(insn.mn);
		if (!mn_name)
			return false;
		result.emplace_back(InstructionToken, mn_name);

		if (insn.op_count)
		{
			size_t mnLen = strlen(mn_name);
			size_t padLen = (mnLen < 10) ? (10 - mnLen) : 1;
			char pad[11];
			memset(pad, ' ', padLen);
			pad[padLen] = '\0';
			result.emplace_back(TextToken, pad);
		}

		/* Operands */
		for (uint8_t i = 0; i < insn.op_count; ++i)
		{
			if (i != 0)
				result.emplace_back(OperandSeparatorToken, ", ");
			tok_operand(insn.ops[i], result);
		}

		return true;
	}

	/* ── GetInstructionLowLevelIL ─────────────────────────────────── */

	bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		if (len < 2)
			return false;

		SH4Instruction insn;
		if (!sh4_decode(data, len, static_cast<uint32_t>(addr), insn))
			return false;

		sh4_lift(this, insn, il);
		len = 2;

		return true;
	}
};

/* ══════════════════════════════════════════════════════════════════════
 *  SH4CallingConvention
 * ══════════════════════════════════════════════════════════════════════ */

class SH4CallingConvention : public CallingConvention
{
public:
	SH4CallingConvention(Architecture* arch) : CallingConvention(arch, "sh4") {}

	vector<uint32_t> GetIntegerArgumentRegisters() override { return {REG_R4, REG_R5, REG_R6, REG_R7}; }

	vector<uint32_t> GetFloatArgumentRegisters() override { return {REG_FR4, REG_FR5, REG_FR6, REG_FR7}; }

	uint32_t GetIntegerReturnValueRegister() override { return REG_R0; }
	uint32_t GetHighIntegerReturnValueRegister() override { return REG_R1; }
	uint32_t GetFloatReturnValueRegister() override { return REG_FR0; }

	vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return {REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14};
	}

	vector<uint32_t> GetCallerSavedRegisters() override
	{
		return {REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6, REG_R7, REG_MACH, REG_MACL, REG_PR, REG_FPSCR};
	}

	vector<uint32_t> GetImplicitlyDefinedRegisters() override { return {REG_R15}; }

	bool AreArgumentRegistersSharedIndex() override { return true; }
};

/* ══════════════════════════════════════════════════════════════════════
 *  Plugin entry point
 * ══════════════════════════════════════════════════════════════════════ */

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
	}
#endif

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		auto* sh4 = new SH4Architecture("sh4");
		Architecture::Register(sh4);

		auto* cc = new SH4CallingConvention(sh4);
		sh4->RegisterCallingConvention(cc);
		sh4->SetDefaultCallingConvention(cc);

		/* Associate sh4 with ELF machine type EM_SH (42) */
		BinaryViewType::RegisterArchitecture("ELF", (1 << 16) | 42 /* EM_SH */, LittleEndian, sh4);

		return true;
	}

} /* extern "C" */
