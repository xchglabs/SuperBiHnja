"""SH-4 Architecture plugin for Binary Ninja."""

from binaryninja import (
    Architecture,
    RegisterInfo,
    InstructionInfo,
    IntrinsicInfo,
    Endianness,
    FlagRole,
    LowLevelILFlagCondition,
    Type,
)

from binaryninja.architecture import IntrinsicInput

from .sh4_decode import decode, get_info, get_text_tokens
from .sh4_lift import lift

class SH4Architecture(Architecture):
    name = 'sh4'
    endianness = Endianness.LittleEndian
    address_size = 4
    default_int_size = 4
    instr_alignment = 2
    max_instr_length = 4

    _decode_cache = (None, None)

    # ── Registers ──────────────────────────────────────────────────────

    regs = {}

    # General-purpose r0-r15 (r15 = sp)
    for _i in range(16):
        _n = f'r{_i}'
        regs[_n] = RegisterInfo(_n, 4)

    # Banked registers r0_bank-r7_bank
    for _i in range(8):
        _n = f'r{_i}_bank'
        regs[_n] = RegisterInfo(_n, 4)

    # Control registers
    for _n in ('sr', 'gbr', 'vbr', 'ssr', 'spc', 'sgr', 'dbr'):
        regs[_n] = RegisterInfo(_n, 4)

    # System registers
    for _n in ('mach', 'macl', 'pr'):
        regs[_n] = RegisterInfo(_n, 4)

    # Program counter
    regs['pc'] = RegisterInfo('pc', 4)

    # FPU control
    regs['fpscr'] = RegisterInfo('fpscr', 4)
    regs['fpul'] = RegisterInfo('fpul', 4)

    # Single-precision FP  fr0-fr15
    for _i in range(16):
        _n = f'fr{_i}'
        regs[_n] = RegisterInfo(_n, 4)

    # Extended bank singles  xf0-xf15
    for _i in range(16):
        _n = f'xf{_i}'
        regs[_n] = RegisterInfo(_n, 4)

    # Double-precision pairs  dr0,dr2,...,dr14
    for _i in range(0, 16, 2):
        _n = f'dr{_i}'
        regs[_n] = RegisterInfo(_n, 8)

    # Extended doubles  xd0,xd2,...,xd14
    for _i in range(0, 16, 2):
        _n = f'xd{_i}'
        regs[_n] = RegisterInfo(_n, 8)

    # Float vectors  fv0,fv4,fv8,fv12
    for _i in range(0, 16, 4):
        _n = f'fv{_i}'
        regs[_n] = RegisterInfo(_n, 16)

    # Cleanup class-level temporaries
    del _i, _n

    # ── Intrinsics ─────────────────────────────────────────────────────

    intrinsics = {
        '__fsca': IntrinsicInfo(
            [IntrinsicInput(Type.int(4), 'angle')],
            [Type.float(4), Type.float(4)],
        ),
        '__sleep': IntrinsicInfo([], []),
    }

    stack_pointer = 'r15'
    link_reg = 'pr'

    # ── Flags (SR.T / S / Q / M) ──────────────────────────────────────

    flags = ['T', 'S', 'Q', 'M']

    flag_roles = {
        'T': FlagRole.SpecialFlagRole,
        'S': FlagRole.SpecialFlagRole,
        'Q': FlagRole.SpecialFlagRole,
        'M': FlagRole.SpecialFlagRole,
    }

    flag_write_types = ['writeT', 'writeTQM']

    flags_written_by_flag_write_type = {
        'writeT': ['T'],
        'writeTQM': ['T', 'Q', 'M'],
    }

    semantic_flag_classes = ['classT']
    semantic_flag_groups = ['groupT']

    # Bind flag-write types to their semantic class
    semantic_class_for_flag_write_type = {
        'writeT': 'classT',
        'writeTQM': 'classT',
    }

    # Which flags the semantic group needs
    flags_required_for_semantic_flag_group = {
        'groupT': ['T'],
    }

    # Map semantic flag group → { semantic_class → flag_condition }
    # 'classT' uses LLFC_E so that BN resolves "flag group == true" as T==1
    flag_conditions_for_semantic_flag_group = {
        'groupT': {
            'classT': LowLevelILFlagCondition.LLFC_E,
        },
    }

    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E:   ['T'],
        LowLevelILFlagCondition.LLFC_NE:  ['T'],
        LowLevelILFlagCondition.LLFC_SLT: ['T'],
        LowLevelILFlagCondition.LLFC_SGE: ['T'],
    }

    # ── Flag IL helpers ───────────────────────────────────────────────

    def get_flag_condition_low_level_il(self, cond, sem_class, il):
        """Return IL expression for a flag condition.

        SH-4 branches test T directly:
          BT  → branch if T == 1  → LLFC_E
          BF  → branch if T == 0  → LLFC_NE
        """
        if cond == LowLevelILFlagCondition.LLFC_E:
            # T == 1
            return il.flag('T')
        if cond == LowLevelILFlagCondition.LLFC_NE:
            # T == 0  →  NOT T
            return il.not_expr(0, il.flag('T'))
        return il.unimplemented()

    def get_semantic_flag_group_low_level_il(self, sem_group, il):
        """Return IL for the groupT semantic flag group → just the T flag."""
        return il.flag('T')

    # ── Instruction delegation ────────────────────────────────────────

    def get_instruction_info(self, data, addr):
        insn = self._cached_decode(data, addr)
        if insn is None:
            return None
        return get_info(insn)

    def get_instruction_text(self, data, addr):
        insn = self._cached_decode(data, addr)
        if insn is None:
            return None
        length = 4 if insn.has_delay_slot else 2
        return get_text_tokens(insn), length

    def get_instruction_low_level_il(self, data, addr, il):
        insn = self._cached_decode(data, addr)
        if insn is None:
            return None
        if insn.has_delay_slot and len(data) >= 4:
            # Lift the delay-slot instruction FIRST, then the branch.
            # BN sees a single 4-byte "instruction" so the slot is never
            # visited independently.
            slot = decode(data[2:], addr + 2)
            if slot is not None:
                lift(slot, il)
            lift(insn, il)
            return 4
        return lift(insn, il)

    def _cached_decode(self, data, addr):
        """Cache last decode — BN calls info/text/IL in sequence per address."""
        ca, ci = self._decode_cache
        if ca == addr:
            return ci
        insn = decode(data, addr)
        self._decode_cache = (addr, insn)
        return insn
