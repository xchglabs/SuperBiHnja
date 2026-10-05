#pragma once
#include "sh4.h"
namespace BinaryNinja {
	class LowLevelILFunction;
	class Architecture;
}  // namespace BinaryNinja
bool sh4_lift(BinaryNinja::Architecture* arch, const SH4Instruction& insn, BinaryNinja::LowLevelILFunction& il);
