"""String + cross-reference recovery for SH-4 firmware.

Why this exists
---------------
SH-4 has no instruction that can hold a 32-bit immediate, so every absolute
address -- including every string pointer -- is loaded from a PC-relative
literal pool via ``mov.l @(disp,PC),Rn``. Binary Ninja reads the load but does
not turn the pooled constant into a data cross-reference. And because a raw
firmware image is mapped as a single executable segment, BN's automatic string
sweep never runs over it either. The net effect: zero detected strings and zero
xrefs.

This module fixes both in two passes:

1. Scan the image for aligned words that point at a printable, NUL-terminated
   byte run and define a C string at the target plus a ``char *`` at the word.
   Defining data inside the executable segment makes BN's own string sweep run,
   which then detects the full string set.
2. For every aligned word whose value equals a now-known string start, define
   it as ``char *``. That creates the string <- pool-word data xref; the
   code -> pool-word reference from the ``mov.l`` load already exists, so the
   full chain becomes code -> pool word -> string.

Pointers stored through an SH P1/P2 mirror window (e.g. a ``__FILE__`` string
referenced via ``0xA8xxxxxx`` while it is mapped at ``0x08xxxxxx``) resolve
too, as long as the mirror is mapped (SH4FirmwareView does this): the target
address is valid, so the string is detected at its mirror address and the pool
word points at it there.

The pass is additive and grouped into a single undo action. It does not save
the database.
"""

import struct

from binaryninja import (BackgroundTaskThread, PluginCommand, SegmentFlag,
                         Settings, Type, log_info)

_MIN_STRLEN = 4
_MAX_STRLEN = 4096

# SH logical memory map: the low 512 MB of physical memory is mirrored through
# a cached and an uncached window that mask to the same 29-bit physical
# address. Derived from whatever base the image is loaded at; no fixed address.
_SH_PHYS_MASK = 0x1FFFFFFF
_SH_MIRROR_WINDOWS = (0x80000000, 0xA0000000)  # P1 (cached), P2 (uncached)


def ensure_mirrors(bv, log=log_info):
    """Map the SH P1/P2 mirror windows of each loaded segment, if absent.

    Needed when recovery runs on a view whose firmware loader did not map the
    mirrors -- e.g. a reopened .bndb or an ELF -- so that pointers stored
    through a mirror window resolve. Idempotent. Returns the count added.
    """
    flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData
    made = 0
    for seg in list(bv.segments):
        if not seg.readable:
            continue
        phys = seg.start & _SH_PHYS_MASK
        for window in _SH_MIRROR_WINDOWS:
            mbase = window | phys
            if mbase != seg.start and not bv.is_valid_offset(mbase):
                try:
                    bv.add_user_segment(mbase, seg.length,
                                        seg.data_offset, seg.data_length, flags)
                    made += 1
                except Exception:
                    pass
    if made:
        log(f'SuperBiHnja: mapped {made} mirror segment(s)')
        bv.update_analysis_and_wait()
    return made


def _readable_buffers(bv):
    """Return [(start, end, bytes)] for readable segments, deduplicated.

    SH P1/P2 mirror segments back the same bytes at different addresses. We
    scan the bytes only once (keeping the lowest-address copy as the canonical
    scan window); mirror-window pointer *targets* still resolve because callers
    use bv.is_valid_offset and a bv.read peek fallback. This keeps the sweep
    from running once per mirror.
    """
    seen = set()
    bufs = []
    for seg in sorted(bv.segments, key=lambda s: s.start):
        if not seg.readable:
            continue
        data = bv.read(seg.start, seg.length)
        if not data:
            continue
        key = hash(data)
        if key in seen:
            continue  # identical mirror already scanned at a lower address
        seen.add(key)
        bufs.append((seg.start, seg.start + len(data), data))
    return bufs


def _make_peek(bv, bufs):
    """Return peek(addr, n) -> bytes, preferring the already-read buffers."""
    def peek(addr, n):
        for start, end, data in bufs:
            if start <= addr < end:
                off = addr - start
                return data[off:off + n]
        return bv.read(addr, n) or b''
    return peek


def _cstr_len(sample):
    """Length of a printable, NUL-terminated C string at the start of `sample`.

    Returns 0 if it is not a plausible string (non-printable byte, or no
    terminator within the sampled window).
    """
    out = 0
    for c in sample:
        if c == 0:
            return out if out >= _MIN_STRLEN else 0
        if not (32 <= c < 127 or c in (9, 10, 13)):
            return 0
        out += 1
    return 0  # no terminator within the window


def _iter_pointer_words(bufs):
    """Yield (word_addr, value) for every 4-aligned 4-byte word in each buffer."""
    for start, _end, data in bufs:
        for i in range(0, len(data) - 4, 4):
            yield start + i, struct.unpack_from('<I', data, i)[0]


def recover_string_xrefs(bv, log=log_info):
    """Detect SH-4 pool strings and wire their cross-references.

    Returns a stats dict:
        {strings_total, pool_pointers_defined, strings_with_xref, pct_with_xref}
    """
    char_ptr = Type.pointer(bv.arch, Type.char())
    bufs = _readable_buffers(bv)
    peek = _make_peek(bv, bufs)

    # --- Pass 1: seed strings/pointers so BN's string sweep activates --------
    seed_targets = {}
    seed_words = []
    for word_addr, value in _iter_pointer_words(bufs):
        if not bv.is_valid_offset(value):
            continue
        length = _cstr_len(peek(value, _MAX_STRLEN + 1))
        if length:
            seed_targets.setdefault(value, length)
            seed_words.append(word_addr)

    log(f'SuperBiHnja: seeding {len(seed_targets)} strings, '
        f'{len(seed_words)} pointers')
    _define(bv, 'recover sh4 string pointers',
            strings=seed_targets, pointers=seed_words, char_ptr=char_ptr)
    bv.update_analysis_and_wait()

    # --- Pass 2: wire every pool word that targets a known string ------------
    str_starts = {s.start for s in bv.strings}
    pool_words = [w for w, v in _iter_pointer_words(bufs) if v in str_starts]

    log(f'SuperBiHnja: defining {len(pool_words)} string-pool pointers')
    _define(bv, 'define sh4 string pool pointers',
            strings={}, pointers=pool_words, char_ptr=char_ptr)
    bv.update_analysis_and_wait()

    total = with_xref = 0
    for s in bv.strings:
        total += 1
        if bv.get_code_refs(s.start) or bv.get_data_refs(s.start):
            with_xref += 1
    stats = {
        'strings_total': total,
        'pool_pointers_defined': len(pool_words),
        'strings_with_xref': with_xref,
        'pct_with_xref': round(100 * with_xref / max(total, 1), 1),
    }
    log(f'SuperBiHnja: {with_xref}/{total} strings now have xrefs '
        f'({stats["pct_with_xref"]}%)')
    return stats


def _define(bv, undo_name, strings, pointers, char_ptr):
    """Define string arrays and char* pointers inside one undo action."""
    def body():
        char_t = Type.char()
        for target, length in strings.items():
            try:
                bv.define_user_data_var(target, Type.array(char_t, length + 1))
            except Exception:
                pass
        for word_addr in pointers:
            try:
                bv.define_user_data_var(word_addr, char_ptr)
            except Exception:
                pass

    tx = getattr(bv, 'undoable_transaction', None)
    if tx is not None:
        with tx():
            body()
    else:  # older API
        state = bv.begin_undo_actions()
        body()
        bv.commit_undo_actions(state)


class _StringRecoveryTask(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__('SuperBiHnja: recovering string xrefs', can_cancel=False)
        self.bv = bv

    def run(self):
        log = lambda m: self.progress_text(m)
        if Settings().get_bool('superbiHnja.firmware.mapMirrors'):
            ensure_mirrors(self.bv, log=log)
        recover_string_xrefs(self.bv, log=log)

    def progress_text(self, msg):
        self.progress = msg
        log_info(msg)


def run_in_background(bv):
    """Start string-xref recovery as a background task."""
    _StringRecoveryTask(bv).start()


def register_plugin_command():
    PluginCommand.register(
        'SuperBiHnja\\Recover SH-4 String Xrefs',
        'Map SH address mirrors, detect literal-pool strings, create their xrefs',
        run_in_background,
    )
