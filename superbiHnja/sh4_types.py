"""
SH-4 instruction representation — shared contract between decoder, disassembler, and lifter.

All three plugin phases (decode, display, lift) operate on SH4Instruction objects.
The decoder produces them from raw bytes; the disassembler renders them as text tokens;
the lifter translates them to Binary Ninja LLIL.
"""

from enum import Enum, IntEnum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Tuple


# ---------------------------------------------------------------------------
# Operand types
# ---------------------------------------------------------------------------

class OperandType(Enum):
    """Every addressing mode in the SH-4 16-bit ISA."""
    REG         = auto()   # Rn
    IMM         = auto()   # #imm (sign-extended or zero-extended per instruction)
    DISP_REG    = auto()   # @(disp, Rn) — disp already scaled by access size
    DISP_PC     = auto()   # @(disp, PC) — resolved to absolute address in .addr
    DISP_GBR    = auto()   # @(disp, GBR)
    AT_REG      = auto()   # @Rn
    AT_REG_POST = auto()   # @Rn+
    AT_PRE_REG  = auto()   # @-Rn
    AT_R0_REG   = auto()   # @(R0, Rn)
    AT_R0_GBR   = auto()   # @(R0, GBR)
    ADDR        = auto()   # Absolute branch/jump target (resolved from PC-relative)
    CTRL_REG    = auto()   # SR, GBR, VBR, SSR, SPC, SGR, DBR
    SYS_REG     = auto()   # MACH, MACL, PR, FPSCR, FPUL
    FR_REG      = auto()   # FRn — single-precision FP register
    DR_REG      = auto()   # DRn — double-precision FP register pair
    XD_REG      = auto()   # XDn — extended double in bank 1
    FV_REG      = auto()   # FVn — float vector (4 singles)
    XMTRX       = auto()   # XMTRX matrix register


# ---------------------------------------------------------------------------
# Branch classification (drives InstructionInfo.add_branch)
# ---------------------------------------------------------------------------

class BranchKind(Enum):
    """How this instruction affects control flow."""
    NONE             = auto()
    UNCOND_DIRECT    = auto()   # BRA, BSR
    UNCOND_INDIRECT  = auto()   # JMP @Rn, RTS, RTE
    COND_TRUE        = auto()   # BT, BT/S (branch if T=1)
    COND_FALSE       = auto()   # BF, BF/S (branch if T=0)
    CALL_DIRECT      = auto()   # BSR
    CALL_INDIRECT    = auto()   # JSR @Rn
    CALL_REG_DIRECT  = auto()   # BSRF Rn
    RETURN           = auto()   # RTS
    EXCEPTION_RETURN = auto()   # RTE
    SYSCALL          = auto()   # TRAPA #imm


# ---------------------------------------------------------------------------
# Operand
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Operand:
    """A single instruction operand.

    Fields used depend on `type`:
      REG / CTRL_REG / SYS_REG / FR_REG / DR_REG / XD_REG / FV_REG / XMTRX:
          reg (str)
      IMM:
          imm (int)
      DISP_REG:
          disp (int, already byte-scaled), reg (str), size (int, access width 1/2/4)
      DISP_PC:
          addr (int, absolute resolved address), size (int, access width 2/4)
      DISP_GBR:
          disp (int, already byte-scaled), size (int, access width 1/2/4)
      AT_REG / AT_REG_POST / AT_PRE_REG:
          reg (str), size (int, access width 1/2/4)
      AT_R0_REG:
          reg (str), size (int, access width 1/2/4)
      AT_R0_GBR:
          size (int, access width 1/2/4)
      ADDR:
          addr (int, absolute target)
    """
    type: OperandType
    reg:  Optional[str] = None
    imm:  Optional[int] = None
    disp: Optional[int] = None
    size: Optional[int] = None   # Memory access width: 1, 2, or 4 bytes
    addr: Optional[int] = None   # Resolved absolute address


# ---------------------------------------------------------------------------
# Decoded instruction
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class SH4Instruction:
    """Fully decoded SH-4 instruction.

    Produced by the decoder; consumed by the disassembler and lifter.
    """
    mnemonic: str                          # e.g. "mov.l", "cmp/eq", "bt/s"
    length: int = 2                        # Always 2 for SH-4 16-bit ISA
    operands: List[Operand] = field(default_factory=list)
    raw: int = 0                           # Raw 16-bit instruction word
    addr: int = 0                          # Address of this instruction

    # Control-flow annotation
    branch: BranchKind = BranchKind.NONE
    has_delay_slot: bool = False           # True for: BRA, BSR, BRAF, BSRF,
                                           #           JMP, JSR, RTS, RTE,
                                           #           BT/S, BF/S
    branch_target: Optional[int] = None    # Resolved target for direct branches


# ---------------------------------------------------------------------------
# Register names (canonical strings used everywhere)
# ---------------------------------------------------------------------------

# General-purpose
REGS_GENERAL = [f"r{i}" for i in range(16)]

# Banked (privileged mode: RB=1 swaps r0-r7 with bank1)
REGS_BANKED = [f"r{i}_bank" for i in range(8)]

# Control registers (accessed via STC/LDC)
REGS_CONTROL = ["sr", "gbr", "vbr", "ssr", "spc", "sgr", "dbr"]

# System registers (accessed via STS/LDS)
REGS_SYSTEM = ["mach", "macl", "pr", "fpscr", "fpul"]

# FPU single-precision
REGS_FR = [f"fr{i}" for i in range(16)]

# FPU extended (bank 1 singles)
REGS_XF = [f"xf{i}" for i in range(16)]

# FPU double-precision pairs (fr0:fr1=dr0, fr2:fr3=dr2, ...)
REGS_DR = [f"dr{i}" for i in range(0, 16, 2)]

# FPU extended doubles (xf0:xf1=xd0, ...)
REGS_XD = [f"xd{i}" for i in range(0, 16, 2)]

# FPU vectors (4 singles each)
REGS_FV = [f"fv{i}" for i in range(0, 16, 4)]

# Program counter (not directly read/written by most instructions, but used
# for PC-relative addressing and by the architecture class)
REG_PC = "pc"

# SR flag bits — the lifter models these as individual flags for Binary Ninja's
# flag condition system.  The architecture class maps them to bit positions in SR.
SR_FLAG_T  = "T"    # bit 0  — condition/result
SR_FLAG_S  = "S"    # bit 1  — saturating arithmetic
SR_FLAG_Q  = "Q"    # bit 8  — division step
SR_FLAG_M  = "M"    # bit 9  — division step

# SR fields that are not modeled as BN flags (treated as part of the SR register):
#   IMASK (bits 7:4), FD (bit 15), BL (bit 28), RB (bit 29), MD (bit 30)


# ---------------------------------------------------------------------------
# Delay-slot mnemonics set (for quick lookup)
# ---------------------------------------------------------------------------

DELAY_SLOT_MNEMONICS = frozenset({
    "bra", "bsr", "braf", "bsrf",
    "jmp", "jsr",
    "rts", "rte",
    "bt/s", "bf/s",
})


# ---------------------------------------------------------------------------
# Instruction groups for the lifter (which flags are written)
# ---------------------------------------------------------------------------

class FlagWrite(Enum):
    """Which SR flags an instruction modifies."""
    NONE  = auto()
    T     = auto()   # CMP/xx, TST, TAS, SETT, CLRT, SHAL, etc.
    T_Q_M = auto()   # DIV0S, DIV0U, DIV1
    T_Q   = auto()   # DIV1 sub-case
