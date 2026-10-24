"""Headless smoke test: load firmware, verify arch, segments, decode, and IL."""
import sys
import os
import binaryninja
from binaryninja import BinaryViewType

def _require_env(name):
    val = os.environ.get(name)
    if not val:
        print(f'Set {name} environment variable', file=sys.stderr)
        sys.exit(1)
    return val

FIRMWARE_BIN = _require_env('SH4_FIRMWARE_BIN')
FIRMWARE_ELF = _require_env('SH4_FIRMWARE_ELF')
KNOWN_FUNC = int(os.environ.get('SH4_KNOWN_FUNC', '0'), 0)


def test_raw_binary_view():
    """Verify raw firmware BinaryView: segments, data access."""
    print(f'Loading raw binary: {FIRMWARE_BIN}')
    raw = BinaryViewType['Raw'].open(FIRMWARE_BIN)
    assert raw is not None, 'Failed to open raw file'

    from superbiHnja.sh4_binaryview import SH4FirmwareView
    bv = SH4FirmwareView(raw)
    ok = bv.init()
    assert ok, 'SH4FirmwareView.init() failed'
    assert bv.arch.name == 'sh4', f'Wrong arch: {bv.arch.name}'
    print(f'  arch={bv.arch.name}, view_type={bv.view_type}')

    segs = list(bv.segments)
    assert len(segs) >= 1, 'No segments found'
    seg = segs[0]
    base = seg.start
    print(f'  firmware segment: {seg.start:#x}-{seg.end:#x} ({seg.data_length} bytes)')
    assert seg.data_length > 0, 'Segment has no data'

    data = bv.read(base, 8)
    assert len(data) == 8, f'Cannot read at {base:#x}: got {len(data)} bytes'
    print(f'  data@{base:#010x}: {data.hex()}')
    assert bv.entry_point == base, f'Wrong entry: {bv.entry_point:#x}'

    bv.file.close()
    print('  PASS: raw binary view')


def test_llil():
    """Verify LLIL generation on real firmware function bytes."""
    if not KNOWN_FUNC:
        print('  SKIP: SH4_KNOWN_FUNC not set')
        return

    print('Testing LLIL on real firmware function...')
    base = int(os.environ.get('SH4_FIRMWARE_BASE', '0'), 0)
    if not base:
        print('  SKIP: SH4_FIRMWARE_BASE not set (needed for LLIL offset)')
        return

    # Extract a 4 KB slice around the known function to avoid full-binary analysis
    with open(FIRMWARE_BIN, 'rb') as f:
        f.seek(KNOWN_FUNC - base)
        chunk = f.read(4096)

    bv = binaryninja.load(chunk, options={
        'loader.platform': 'sh4',
        'analysis.linearSweep.autorun': False,
    })
    assert bv.arch.name == 'sh4', f'Wrong arch: {bv.arch.name}'
    analysis_start = bv.entry_point
    assert analysis_start is not None, 'Loaded view has no entry point'

    bv.add_function(analysis_start)
    bv.update_analysis_and_wait()

    fn = bv.get_function_at(analysis_start)
    assert fn is not None, 'Function not created from firmware bytes'
    llil = fn.low_level_il
    assert llil is not None, 'No LLIL for function'
    insn_count = sum(len(list(block)) for block in llil)
    print(f'  LLIL@{analysis_start:08x} (source FUN_{KNOWN_FUNC:08x}): {insn_count} LLIL instructions')
    assert insn_count > 0, 'LLIL is empty'

    # Show first few LLIL instructions as proof
    for block in llil:
        for insn in list(block)[:5]:
            print(f'    {insn.address:#010x}: {insn}')
        break

    bv.file.close()
    print('  PASS: LLIL')


def test_elf():
    """Verify ELF loads with sh4 architecture via EM_SH registration."""
    print(f'Loading ELF: {FIRMWARE_ELF}')
    bv = binaryninja.load(FIRMWARE_ELF, update_analysis=False)
    assert bv is not None, 'Failed to load ELF'
    assert bv.arch.name == 'sh4', f'Wrong arch: {bv.arch.name}'
    print(f'  arch={bv.arch.name}, view_type={bv.view_type}')
    print(f'  entry: {bv.entry_point:#x}')

    segs = list(bv.segments)
    print(f'  segments: {len(segs)}')
    assert len(segs) > 0, 'ELF has no segments'

    data = bv.read(bv.entry_point, 4)
    assert len(data) == 4, f'Cannot read at entry: got {len(data)} bytes'
    print(f'  data@entry: {data.hex()}')

    bv.file.close()
    print('  PASS: ELF')


def test_plugin_registration():
    """Verify the setting and plugin command registered on import."""
    from binaryninja import PluginCommand, Settings
    import superbiHnja  # noqa: F401 -- triggers registration side effects

    assert Settings().contains('superbiHnja.firmware.recoverStrings'), \
        'recoverStrings setting not registered'
    names = [c.name for c in PluginCommand]
    cmd = 'SuperBiHnja\\Recover SH-4 String Xrefs'
    assert cmd in names, f'command not registered; have: {names}'
    print('  PASS: setting + command registered')


def test_string_recovery():
    """Verify recover_string_xrefs creates the pool-word -> string xref chain."""
    import struct
    from superbiHnja.sh4_strings import recover_string_xrefs

    STR_ADDR = 0x40
    PTR_ADDR = 0x10
    chunk = bytearray(0x80)
    chunk[STR_ADDR:STR_ADDR + 10] = b'HELLO_SH4\x00'
    chunk[PTR_ADDR:PTR_ADDR + 4] = struct.pack('<I', STR_ADDR)  # pool pointer

    print('Testing string-xref recovery on a synthetic image...')
    bv = binaryninja.load(bytes(chunk), options={
        'loader.platform': 'sh4',
        'analysis.linearSweep.autorun': False,
    })
    assert bv.arch.name == 'sh4', f'Wrong arch: {bv.arch.name}'

    stats = recover_string_xrefs(bv, log=lambda m: None)
    print(f'  stats: {stats}')

    starts = {s.start for s in bv.strings}
    assert STR_ADDR in starts, f'string at {STR_ADDR:#x} not detected'

    refs = list(bv.get_data_refs(STR_ADDR))
    assert PTR_ADDR in refs, f'no xref from pool word {PTR_ADDR:#x}; refs={[hex(r) for r in refs]}'

    var = bv.get_data_var_at(PTR_ADDR)
    assert var is not None and var.type.type_class == binaryninja.TypeClass.PointerTypeClass, \
        'pool word not typed as pointer'

    bv.file.close()
    print('  PASS: string recovery')


def test_mirror_recovery():
    """Verify recovery auto-maps SH mirrors so a mirror-window pointer resolves.

    Simulates a reopened .bndb: the pointer is stored through the uncached
    mirror window, which is NOT mapped up front. ensure_mirrors (the command
    path) must map it so the pointer resolves to its string.
    """
    import struct
    from superbiHnja.sh4_strings import recover_string_xrefs, ensure_mirrors

    STR_OFF, PTR_OFF = 0x40, 0x10
    MIRROR = 0xA0000000  # P2 (uncached) mirror of physical 0
    chunk = bytearray(0x100)
    chunk[STR_OFF:STR_OFF + 9] = b'MIRRORED\x00'
    chunk[PTR_OFF:PTR_OFF + 4] = struct.pack('<I', MIRROR + STR_OFF)  # ptr via mirror

    print('Testing mirror-window string recovery...')
    bv = binaryninja.load(bytes(chunk), options={
        'loader.platform': 'sh4',
        'analysis.linearSweep.autorun': False,
    })
    assert not bv.is_valid_offset(MIRROR + STR_OFF), 'mirror should not be mapped yet'
    assert ensure_mirrors(bv, log=lambda m: None) >= 1, 'no mirror mapped'
    recover_string_xrefs(bv, log=lambda m: None)

    mstr = MIRROR + STR_OFF
    assert any(s.start == mstr for s in bv.strings), 'mirror string not detected'
    refs = list(bv.get_data_refs(mstr))
    assert PTR_OFF in refs, f'no xref from pool word; refs={[hex(r) for r in refs]}'

    bv.file.close()
    print('  PASS: mirror recovery')


if __name__ == '__main__':
    ok = True
    for test in [test_raw_binary_view, test_llil, test_elf,
                 test_plugin_registration, test_string_recovery,
                 test_mirror_recovery]:
        try:
            test()
        except Exception as e:
            print(f'  FAIL: {e}', file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            ok = False
    sys.exit(0 if ok else 1)
