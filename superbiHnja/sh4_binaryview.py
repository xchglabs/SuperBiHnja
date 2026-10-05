"""BinaryView for loading raw SH-4 firmware images."""

import struct

from binaryninja import BinaryView, Settings, SegmentFlag, SectionSemantics
from binaryninja import log_info

# Common SH-4 function prologue opcodes (little-endian 16-bit)
_PROLOGUE_PUSH_FP = 0x2FE6   # mov.l r14, @-r15
_PROLOGUE_PUSH_PR = 0x4F22   # sts.l pr, @-r15


class SH4FirmwareView(BinaryView):
    name = 'SH4-Firmware'
    long_name = 'SH-4 Raw Firmware'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        import binaryninja
        self.arch = binaryninja.Architecture['sh4']
        self.platform = self.arch.standalone_platform
        self._raw = data

    # Little-endian bytes for the prologue pair mov.l r14,@-r15 ; sts.l pr,@-r15
    _PROLOGUE_SIG = struct.pack('<HH', _PROLOGUE_PUSH_FP, _PROLOGUE_PUSH_PR)

    @classmethod
    def is_valid_for_data(cls, data):
        # Headerless SH-4 firmware has no magic. Detect it heuristically by
        # the standard function prologue (mov.l r14,@-r15 ; sts.l pr,@-r15).
        # These are sparse near the top of a firmware image and dense in the
        # code region deeper in, so scan the whole file. bytes.count is a
        # C-level scan — fast even on a multi-MB image — and the 4-byte
        # signature is specific enough that a handful of hits is conclusive.
        length = data.length
        if length < 4:
            return False
        raw = data.read(0, length)
        return raw.count(cls._PROLOGUE_SIG) >= 4

    def init(self):
        base_str = Settings().get_string('superbiHnja.firmware.baseAddress')
        self._base = int(base_str, 0) if base_str else 0
        length = self._raw.length
        raw = self._raw.read(0, length)

        base = self._base

        # Map the whole image as readable + executable. A firmware blob has
        # executable code (reset/vector stubs) before the first C-style
        # prologue, so a non-executable "data" segment there would hide it.
        # The pre-prologue region is annotated as a data *section* instead,
        # which keeps it executable while still marking it as data.
        seg_flags = (SegmentFlag.SegmentReadable
                     | SegmentFlag.SegmentExecutable
                     | SegmentFlag.SegmentContainsCode
                     | SegmentFlag.SegmentContainsData)
        self.add_auto_segment(base, length, 0, length, seg_flags)

        # First prologue marks where compiler-generated functions begin.
        code_start = self._find_code_start(raw)
        if code_start > 0:
            self.add_auto_section('data', base, code_start,
                                  SectionSemantics.ReadOnlyDataSectionSemantics)
        self.add_auto_section('code', base + code_start, length - code_start,
                              SectionSemantics.ReadOnlyCodeSectionSemantics)

        # Seed the entry point, then every prologue across the whole image.
        self.add_function(base)
        count = self._scan_prologues(raw, 0)
        log_info(f'SuperBiHnja: data 0-{code_start:#x}, code {code_start:#x}-{length:#x}, '
                 f'seeded {count} functions')
        return True

    @staticmethod
    def _find_code_start(raw):
        """Return file offset of the first function prologue (2-byte aligned)."""
        for i in range(0, len(raw) - 3, 2):
            w0 = struct.unpack_from('<H', raw, i)[0]
            w1 = struct.unpack_from('<H', raw, i + 2)[0]
            if w0 == _PROLOGUE_PUSH_FP and w1 == _PROLOGUE_PUSH_PR:
                return i
        return 0

    def _scan_prologues(self, raw, start_offset):
        """Scan for function prologues starting at start_offset."""
        base = self._base
        count = 0
        for i in range(start_offset, len(raw) - 3, 2):
            w0 = struct.unpack_from('<H', raw, i)[0]
            w1 = struct.unpack_from('<H', raw, i + 2)[0]
            if w0 == _PROLOGUE_PUSH_FP and w1 == _PROLOGUE_PUSH_PR:
                self.add_function(base + i)
                count += 1
        return count

    def perform_is_executable(self):
        return True

    def perform_get_address_size(self):
        return 4

    def perform_get_entry_point(self):
        return getattr(self, '_base', 0)
