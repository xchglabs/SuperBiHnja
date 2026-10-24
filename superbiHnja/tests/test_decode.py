"""Decoder validation tests against capstone and known firmware functions.

Run: python -m pytest superbiHnja/tests/test_decode.py -v
  or: python -m unittest superbiHnja.tests.test_decode -v
"""

import os
import struct
import unittest
from pathlib import Path

from superbiHnja.sh4_types import (
    BranchKind,
    OperandType,
    SH4Instruction,
)

# Paths — require env vars, no hardcoded fallbacks
_FIRMWARE_PATH = Path(os.environ['SH4_FIRMWARE_BIN']) if 'SH4_FIRMWARE_BIN' in os.environ else None
_FUNCTIONS_TSV = Path(os.environ['SH4_FUNCTIONS_TSV']) if 'SH4_FUNCTIONS_TSV' in os.environ else None
_FIRMWARE_BASE = int(os.environ.get('SH4_FIRMWARE_BASE', '0'), 0) or 0x08000000


def _decode(raw_bytes: bytes, addr: int = 0) -> SH4Instruction:
    """Decode a single instruction via our decoder."""
    from superbiHnja.sh4_decode import decode
    insn = decode(raw_bytes, addr)
    if insn is None:
        raise ValueError(f'Decoder returned None for {raw_bytes.hex()} at 0x{addr:08x}')
    return insn


def _read_firmware_at(addr: int, size: int) -> bytes:
    """Read `size` bytes from the firmware at virtual address `addr`."""
    with open(_FIRMWARE_PATH, 'rb') as f:
        f.seek(addr - _FIRMWARE_BASE)
        return f.read(size)


def _decode_block(start_addr: int, size: int):
    """Decode a contiguous block of instructions. Yields SH4Instruction."""
    data = _read_firmware_at(start_addr, size)
    offset = 0
    while offset + 1 < size:
        insn = _decode(data[offset:offset + 2], start_addr + offset)
        yield insn
        offset += 2


class TestKnownInstructions(unittest.TestCase):
    """Decode specific byte sequences and verify mnemonic, operands, branch info."""

    def test_mov_l_reg_at_pre_reg(self):
        """0xe6, 0x2f → mov.l r14, @-r15"""
        insn = _decode(bytes([0xe6, 0x2f]))
        self.assertEqual(insn.mnemonic, 'mov.l')
        self.assertEqual(len(insn.operands), 2)
        # Source: r14
        self.assertEqual(insn.operands[0].type, OperandType.REG)
        self.assertEqual(insn.operands[0].reg, 'r14')
        # Dest: @-r15 (pre-decrement)
        self.assertEqual(insn.operands[1].type, OperandType.AT_PRE_REG)
        self.assertEqual(insn.operands[1].reg, 'r15')
        self.assertEqual(insn.operands[1].size, 4)

    def test_sts_l_pr_at_pre_reg(self):
        """0x22, 0x4f → sts.l pr, @-r15"""
        insn = _decode(bytes([0x22, 0x4f]))
        self.assertEqual(insn.mnemonic, 'sts.l')
        self.assertEqual(len(insn.operands), 2)
        # Source: system register PR
        self.assertEqual(insn.operands[0].type, OperandType.SYS_REG)
        self.assertEqual(insn.operands[0].reg, 'pr')
        # Dest: @-r15
        self.assertEqual(insn.operands[1].type, OperandType.AT_PRE_REG)
        self.assertEqual(insn.operands[1].reg, 'r15')

    def test_mov_l_disp_pc(self):
        """0x07, 0xd1 at 0x08b3d364 → mov.l @(0x1c, PC), r1
        Resolved addr = (0x08b3d364 & ~3) + 4 + 7*4 = 0x08b3d384
        """
        insn = _decode(bytes([0x07, 0xd1]), addr=0x08b3d364)
        self.assertEqual(insn.mnemonic, 'mov.l')
        self.assertEqual(len(insn.operands), 2)
        # Source: PC-relative with resolved address
        self.assertEqual(insn.operands[0].type, OperandType.DISP_PC)
        self.assertEqual(insn.operands[0].addr, 0x08b3d384)
        self.assertEqual(insn.operands[0].size, 4)
        # Dest: r1
        self.assertEqual(insn.operands[1].type, OperandType.REG)
        self.assertEqual(insn.operands[1].reg, 'r1')

    def test_mov_imm(self):
        """0x14, 0xe0 → mov #0x14, r0"""
        insn = _decode(bytes([0x14, 0xe0]))
        self.assertEqual(insn.mnemonic, 'mov')
        self.assertEqual(len(insn.operands), 2)
        # Source: immediate
        self.assertEqual(insn.operands[0].type, OperandType.IMM)
        self.assertEqual(insn.operands[0].imm, 0x14)
        # Dest: r0
        self.assertEqual(insn.operands[1].type, OperandType.REG)
        self.assertEqual(insn.operands[1].reg, 'r0')

    def test_jsr_indirect(self):
        """0x0b, 0x47 → jsr @r7 (has_delay_slot, CALL_INDIRECT)"""
        insn = _decode(bytes([0x0b, 0x47]))
        self.assertEqual(insn.mnemonic, 'jsr')
        self.assertTrue(insn.has_delay_slot)
        self.assertEqual(insn.branch, BranchKind.CALL_INDIRECT)
        self.assertEqual(insn.operands[0].type, OperandType.AT_REG)
        self.assertEqual(insn.operands[0].reg, 'r7')

    def test_bra(self):
        """0x01, 0xa0 → bra (has_delay_slot, UNCOND_DIRECT)"""
        insn = _decode(bytes([0x01, 0xa0]), addr=0)
        self.assertEqual(insn.mnemonic, 'bra')
        self.assertTrue(insn.has_delay_slot)
        self.assertEqual(insn.branch, BranchKind.UNCOND_DIRECT)
        # Target = PC + 4 + 1*2 = 6
        self.assertEqual(insn.branch_target, 6)

    def test_bf_s(self):
        """0x32, 0x8f at 0x08b3d36c → bf/s (has_delay_slot, COND_FALSE)
        Target = 0x08b3d36c + 4 + 0x32*2 = 0x08b3d3d4
        """
        insn = _decode(bytes([0x32, 0x8f]), addr=0x08b3d36c)
        self.assertEqual(insn.mnemonic, 'bf/s')
        self.assertTrue(insn.has_delay_slot)
        self.assertEqual(insn.branch, BranchKind.COND_FALSE)
        self.assertEqual(insn.branch_target, 0x08b3d3d4)

    def test_rts(self):
        """0x0b, 0x00 → rts (has_delay_slot, RETURN)"""
        insn = _decode(bytes([0x0b, 0x00]))
        self.assertEqual(insn.mnemonic, 'rts')
        self.assertTrue(insn.has_delay_slot)
        self.assertEqual(insn.branch, BranchKind.RETURN)

    def test_sts_fpscr(self):
        """0x6a, 0x02 → sts fpscr, r2 (SYS_REG fpscr)"""
        insn = _decode(bytes([0x6a, 0x02]))
        self.assertEqual(insn.mnemonic, 'sts')
        self.assertEqual(len(insn.operands), 2)
        self.assertEqual(insn.operands[0].type, OperandType.SYS_REG)
        self.assertEqual(insn.operands[0].reg, 'fpscr')
        self.assertEqual(insn.operands[1].type, OperandType.REG)
        self.assertEqual(insn.operands[1].reg, 'r2')

    def test_lds_fpscr(self):
        """0x6a, 0x42 → lds r2, fpscr"""
        insn = _decode(bytes([0x6a, 0x42]))
        self.assertEqual(insn.mnemonic, 'lds')
        self.assertEqual(len(insn.operands), 2)
        self.assertEqual(insn.operands[0].type, OperandType.REG)
        self.assertEqual(insn.operands[0].reg, 'r2')
        self.assertEqual(insn.operands[1].type, OperandType.SYS_REG)
        self.assertEqual(insn.operands[1].reg, 'fpscr')

    def test_stc_sr(self):
        """0x02, 0x00 → stc sr, r0 (CTRL_REG sr)"""
        insn = _decode(bytes([0x02, 0x00]))
        self.assertEqual(insn.mnemonic, 'stc')
        self.assertEqual(len(insn.operands), 2)
        self.assertEqual(insn.operands[0].type, OperandType.CTRL_REG)
        self.assertEqual(insn.operands[0].reg, 'sr')
        self.assertEqual(insn.operands[1].type, OperandType.REG)
        self.assertEqual(insn.operands[1].reg, 'r0')

    def test_ldc_sr(self):
        """0x0e, 0x40 → ldc r0, sr"""
        insn = _decode(bytes([0x0e, 0x40]))
        self.assertEqual(insn.mnemonic, 'ldc')
        self.assertEqual(len(insn.operands), 2)
        self.assertEqual(insn.operands[0].type, OperandType.REG)
        self.assertEqual(insn.operands[0].reg, 'r0')
        self.assertEqual(insn.operands[1].type, OperandType.CTRL_REG)
        self.assertEqual(insn.operands[1].reg, 'sr')


class TestCapstoneAgreement(unittest.TestCase):
    """Compare our decoder against capstone for real firmware functions."""

    @unittest.skipUnless(_FIRMWARE_PATH is not None and _FIRMWARE_PATH.exists(), 'firmware not available')
    @unittest.skipUnless(_FUNCTIONS_TSV is not None and _FUNCTIONS_TSV.exists(), 'functions TSV not available')
    def test_capstone_agreement(self):
        """Decode first 100 functions: our mnemonics should agree with capstone >99%."""
        import csv
        from capstone import Cs, CS_ARCH_SH, CS_MODE_SH4, CS_MODE_LITTLE_ENDIAN

        md = Cs(CS_ARCH_SH, CS_MODE_SH4 | CS_MODE_LITTLE_ENDIAN)

        # Read first 100 functions from TSV
        functions = []
        with open(_FUNCTIONS_TSV, 'r') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for i, row in enumerate(reader):
                if i >= 100:
                    break
                addr = int(row['address'], 16)
                size = int(row['size'])
                functions.append((addr, size))

        total = 0
        disagreements = 0
        capstone_failures = 0
        details = []

        for func_addr, func_size in functions:
            # Clamp size for safety and only decode contiguous first block
            decode_size = min(func_size, 256)
            try:
                data = _read_firmware_at(func_addr, decode_size)
            except Exception:
                continue

            for offset in range(0, decode_size, 2):
                if offset + 1 >= len(data):
                    break
                insn_bytes = data[offset:offset + 2]
                addr = func_addr + offset

                # Capstone decode
                cap_insns = list(md.disasm(insn_bytes, addr))
                if not cap_insns:
                    capstone_failures += 1
                    continue

                cap_mnemonic = cap_insns[0].mnemonic
                # Strip leading underscore (capstone uses _mov for delay slot)
                if cap_mnemonic.startswith('_'):
                    cap_mnemonic = cap_mnemonic[1:]

                # Our decoder
                try:
                    our_insn = _decode(insn_bytes, addr)
                    our_mnemonic = our_insn.mnemonic
                except Exception:
                    disagreements += 1
                    total += 1
                    continue

                total += 1
                if our_mnemonic != cap_mnemonic:
                    disagreements += 1
                    if len(details) < 20:
                        details.append(
                            f'  0x{addr:08x}: ours={our_mnemonic!r} '
                            f'cap={cap_mnemonic!r} ({insn_bytes.hex()})'
                        )

        # Report
        if total > 0:
            rate = disagreements / total
            msg = (
                f'Disagreement rate: {disagreements}/{total} = {rate:.2%}\n'
                f'Capstone decode failures (skipped): {capstone_failures}\n'
            )
            if details:
                msg += 'First disagreements:\n' + '\n'.join(details)
            self.assertLess(rate, 0.01, msg)
        else:
            self.skipTest('No instructions decoded')


class TestFunctionBoundaries(unittest.TestCase):
    """Validate FUN_08b3d360 (66 bytes, non-contiguous blocks)."""

    @unittest.skipUnless(_FIRMWARE_PATH is not None and _FIRMWARE_PATH.exists(), 'firmware not available')
    def test_fun_08b3d360(self):
        """Decode FUN_08b3d360 and verify structural properties.

        Ghidra shows two code blocks:
          Block 1: 0x08b3d360 - 0x08b3d37a (13 instructions, 26 bytes)
          Block 2: 0x08b3d3d4 - 0x08b3d3fc (20 instructions, 40 bytes)
        Total: 66 bytes
        """
        # Block 1: from function entry to bra delay slot
        block1 = list(_decode_block(0x08b3d360, 26))
        # Block 2: bf/s target through rts delay slot
        block2 = list(_decode_block(0x08b3d3d4, 40))
        all_insns = block1 + block2

        # 1. First instruction is mov.l r14, @-r15
        self.assertEqual(block1[0].mnemonic, 'mov.l')
        self.assertEqual(block1[0].operands[0].reg, 'r14')
        self.assertEqual(block1[0].operands[1].type, OperandType.AT_PRE_REG)
        self.assertEqual(block1[0].operands[1].reg, 'r15')

        # 2. Contains bf/s with delay slot
        bf_s_insns = [i for i in all_insns if i.mnemonic == 'bf/s']
        self.assertTrue(len(bf_s_insns) > 0, 'No bf/s found')
        for bfs in bf_s_insns:
            self.assertTrue(bfs.has_delay_slot)
            self.assertEqual(bfs.branch, BranchKind.COND_FALSE)

        # 3. Contains sts fpscr, r2 and lds rN, fpscr
        sts_fpscr = [i for i in all_insns
                     if i.mnemonic == 'sts'
                     and any(op.type == OperandType.SYS_REG and op.reg == 'fpscr'
                             for op in i.operands)]
        self.assertTrue(len(sts_fpscr) > 0, 'No sts fpscr found')

        lds_fpscr = [i for i in all_insns
                     if i.mnemonic == 'lds'
                     and any(op.type == OperandType.SYS_REG and op.reg == 'fpscr'
                             for op in i.operands)]
        self.assertTrue(len(lds_fpscr) > 0, 'No lds fpscr found')

        # 4. Last instruction before function end includes rts
        # rts is the second-to-last instruction (followed by its delay slot)
        rts_insns = [i for i in all_insns if i.mnemonic == 'rts']
        self.assertTrue(len(rts_insns) > 0, 'No rts found')
        # The rts in block2 should be near the end
        rts_in_block2 = [i for i in block2 if i.mnemonic == 'rts']
        self.assertTrue(len(rts_in_block2) > 0, 'No rts in block2')
        # rts at 0x08b3d3f8 is second-to-last (delay slot at 0x08b3d3fa)
        self.assertEqual(rts_in_block2[-1].addr, 0x08b3d3f8)

        # 5. Branch targets within function or at known addresses
        func_block1_range = range(0x08b3d360, 0x08b3d37a)
        func_block2_range = range(0x08b3d3d4, 0x08b3d3fc)
        for insn in all_insns:
            if insn.branch_target is not None:
                target = insn.branch_target
                in_func = (target in func_block1_range or
                           target in func_block2_range)
                # Allow targets just past function end (fall-through) or
                # to known code outside (bf/s target, bra target)
                if not in_func:
                    # These are legitimate: bf/s→0x08b3d3d4 (block2 start),
                    # bra→0x08b3d3f6 (within block2), bt/s→0x08b3d3f4 (block2)
                    # All should be within the combined function range
                    self.assertTrue(
                        target in func_block2_range or target in func_block1_range,
                        f'Branch target 0x{target:08x} from 0x{insn.addr:08x} '
                        f'({insn.mnemonic}) outside function'
                    )


class TestSRFunction(unittest.TestCase):
    """Validate FUN_08dfd174: SR manipulation instructions."""

    @unittest.skipUnless(_FIRMWARE_PATH is not None and _FIRMWARE_PATH.exists(), 'firmware not available')
    def test_fun_08dfd174(self):
        """Decode FUN_08dfd174 (14 bytes) and verify stc sr and ldc sr."""
        insns = list(_decode_block(0x08dfd174, 14))

        # Should have 7 instructions (14 bytes / 2)
        self.assertEqual(len(insns), 7)

        # Verify stc sr, r0 is present (at 0x08dfd176)
        stc_sr = [i for i in insns
                  if i.mnemonic == 'stc'
                  and any(op.type == OperandType.CTRL_REG and op.reg == 'sr'
                          for op in i.operands)]
        self.assertTrue(len(stc_sr) > 0, 'No stc sr found')
        # stc sr, r0: source is CTRL_REG sr, dest is REG r0
        stc = stc_sr[0]
        self.assertEqual(stc.operands[0].type, OperandType.CTRL_REG)
        self.assertEqual(stc.operands[0].reg, 'sr')
        self.assertEqual(stc.operands[1].type, OperandType.REG)
        self.assertEqual(stc.operands[1].reg, 'r0')

        # Verify ldc rN, sr is present (at 0x08dfd17c)
        ldc_sr = [i for i in insns
                  if i.mnemonic == 'ldc'
                  and any(op.type == OperandType.CTRL_REG and op.reg == 'sr'
                          for op in i.operands)]
        self.assertTrue(len(ldc_sr) > 0, 'No ldc sr found')
        ldc = ldc_sr[0]
        self.assertEqual(ldc.operands[0].type, OperandType.REG)
        self.assertEqual(ldc.operands[1].type, OperandType.CTRL_REG)
        self.assertEqual(ldc.operands[1].reg, 'sr')

        # Verify rts is present (at 0x08dfd17e)
        rts_insns = [i for i in insns if i.mnemonic == 'rts']
        self.assertTrue(len(rts_insns) > 0, 'No rts found')
        self.assertTrue(rts_insns[0].has_delay_slot)


if __name__ == '__main__':
    unittest.main()
