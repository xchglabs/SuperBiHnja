#!/usr/bin/env python3
"""Compare SuperBiHnja SH-4 decoder against Ghidra .asm reference files.

Usage:
    python3 scripts/validate_ghidra.py

Run from the project root (SuperBiHnja/).  No Binary Ninja dependency.
"""

import os
import sys
from collections import Counter
from pathlib import Path

# Ensure project root is on sys.path so we can import superbiHnja
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from superbiHnja.sh4_decode import decode

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _require_env(name):
    val = os.environ.get(name)
    if not val:
        print(f'Set {name} environment variable', file=sys.stderr)
        sys.exit(1)
    return val

FIRMWARE_BIN = Path(_require_env('SH4_FIRMWARE_BIN'))
GHIDRA_ASM_DIR = Path(_require_env('SH4_GHIDRA_ASM_DIR'))
FIRMWARE_BASE = int(os.environ.get('SH4_FIRMWARE_BASE', '0x08000000'), 0)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_ghidra_asm(path: Path):
    """Parse a Ghidra .asm file into a list of (addr, mnemonic, operands).

    Skips comment lines (';'), blank lines, and lines that don't start with
    a hex address.  Strips the delay-slot '_' prefix from mnemonics.
    """
    insns = []
    func_name = None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(";"):
            # Extract function name from header comment
            if func_name is None and "Function:" in stripped:
                # "; Function: FUN_08b3d360 @ 0x08b3d360"
                parts = stripped.split("Function:")
                if len(parts) > 1:
                    func_name = parts[1].strip().split()[0]
            continue
        # Instruction lines: "<hex_addr>  <mnemonic>  [operands]"
        parts = stripped.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        mnemonic = parts[1]
        # Strip delay-slot underscore prefix
        if mnemonic.startswith("_"):
            mnemonic = mnemonic[1:]
        operands = parts[2] if len(parts) > 2 else ""
        insns.append((addr, mnemonic, operands))
    return func_name or path.stem, insns


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_function(firmware: bytes, func_name: str, ghidra_insns):
    """Decode each instruction and compare mnemonic against Ghidra.

    Returns (matches, total, list_of_mismatches).
    Each mismatch is (addr, ghidra_mnem, decoder_mnem).
    """
    matches = 0
    total = 0
    mismatches = []

    for addr, g_mnem, g_ops in ghidra_insns:
        offset = addr - FIRMWARE_BASE
        if offset < 0 or offset + 2 > len(firmware):
            mismatches.append((addr, g_mnem, "<out-of-range>"))
            total += 1
            continue

        raw = firmware[offset : offset + 2]
        insn = decode(raw, addr)
        total += 1

        if insn is None:
            decoder_mnem = "<decode-fail>"
        else:
            decoder_mnem = insn.mnemonic

        if g_mnem.lower() == decoder_mnem.lower():
            matches += 1
        else:
            mismatches.append((addr, g_mnem, decoder_mnem))

    return matches, total, mismatches


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Validate paths
    if not FIRMWARE_BIN.exists():
        print(f"ERROR: firmware not found: {FIRMWARE_BIN}", file=sys.stderr)
        sys.exit(1)
    if not GHIDRA_ASM_DIR.is_dir():
        print(f"ERROR: asm directory not found: {GHIDRA_ASM_DIR}", file=sys.stderr)
        sys.exit(1)

    asm_files = sorted(GHIDRA_ASM_DIR.glob("*.asm"))
    if not asm_files:
        print("ERROR: no .asm files found", file=sys.stderr)
        sys.exit(1)

    firmware = FIRMWARE_BIN.read_bytes()

    print(f"Firmware : {FIRMWARE_BIN.name} ({len(firmware):,} bytes)")
    print(f"ASM dir  : {GHIDRA_ASM_DIR}")
    print(f"Files    : {len(asm_files)}")
    print(f"Base addr: 0x{FIRMWARE_BASE:08X}")
    print()

    # Per-function results
    total_matches = 0
    total_insns = 0
    all_mismatches = []          # (func_name, addr, ghidra, decoder)
    mismatch_patterns = Counter()  # ("ghidra_mnem", "decoder_mnem") -> count
    func_results = []            # (func_name, matches, total)
    skipped_empty = 0

    for asm_path in asm_files:
        func_name, ghidra_insns = parse_ghidra_asm(asm_path)

        if not ghidra_insns:
            skipped_empty += 1
            continue

        matches, total, mismatches = compare_function(
            firmware, func_name, ghidra_insns
        )

        total_matches += matches
        total_insns += total
        func_results.append((func_name, matches, total))

        for addr, g_mnem, d_mnem in mismatches:
            all_mismatches.append((func_name, addr, g_mnem, d_mnem))
            mismatch_patterns[(g_mnem.lower(), d_mnem.lower())] += 1

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------

    # -- Per-function results -----------------------------------------------
    print("=" * 72)
    print("  PER-FUNCTION RESULTS")
    print("=" * 72)
    print(f"{'Function':<24s} {'Match':>7s} {'Total':>7s} {'Rate':>8s}")
    print("-" * 72)

    for func_name, matches, total in func_results:
        pct = 100.0 * matches / total if total else 0.0
        marker = "" if pct == 100.0 else "  ***"
        print(f"{func_name:<24s} {matches:>7d} {total:>7d} {pct:>7.1f}%{marker}")

    # -- Overall summary ----------------------------------------------------
    print()
    print("=" * 72)
    print("  OVERALL SUMMARY")
    print("=" * 72)
    overall_pct = 100.0 * total_matches / total_insns if total_insns else 0.0
    print(f"  Functions analysed : {len(func_results)}")
    if skipped_empty:
        print(f"  Empty files skipped: {skipped_empty}")
    print(f"  Total instructions : {total_insns:,}")
    print(f"  Matches            : {total_matches:,}")
    print(f"  Mismatches         : {total_insns - total_matches:,}")
    print(f"  Agreement          : {overall_pct:.2f}%")

    # -- Worst functions ----------------------------------------------------
    imperfect = [
        (name, m, t) for name, m, t in func_results if m < t
    ]
    if imperfect:
        imperfect.sort(key=lambda x: x[1] / x[2] if x[2] else 0)
        print()
        print("=" * 72)
        print("  FUNCTIONS WITH LOWEST MATCH RATES")
        print("=" * 72)
        print(f"{'Function':<24s} {'Match':>7s} {'Total':>7s} {'Rate':>8s}")
        print("-" * 72)
        for func_name, matches, total in imperfect[:20]:
            pct = 100.0 * matches / total if total else 0.0
            print(f"{func_name:<24s} {matches:>7d} {total:>7d} {pct:>7.1f}%")

    # -- Mismatch patterns --------------------------------------------------
    if mismatch_patterns:
        print()
        print("=" * 72)
        print("  UNIQUE MISMATCH PATTERNS")
        print("=" * 72)
        print(f"{'Ghidra':<20s} {'Decoder':<20s} {'Count':>7s}")
        print("-" * 72)
        for (g, d), count in mismatch_patterns.most_common(30):
            print(f"{g:<20s} {d:<20s} {count:>7d}")

    # -- Sample mismatches --------------------------------------------------
    if all_mismatches:
        print()
        print("=" * 72)
        print(f"  FIRST {min(50, len(all_mismatches))} MISMATCHES (of {len(all_mismatches)} total)")
        print("=" * 72)
        print(f"{'Address':<12s} {'Function':<24s} {'Ghidra':<16s} {'Decoder':<16s}")
        print("-" * 72)
        for func_name, addr, g_mnem, d_mnem in all_mismatches[:50]:
            print(f"0x{addr:08X}   {func_name:<24s} {g_mnem:<16s} {d_mnem:<16s}")

    # -- Exit code ----------------------------------------------------------
    print()
    if total_insns == total_matches:
        print("RESULT: PERFECT AGREEMENT — all mnemonics match.")
    elif overall_pct >= 99.0:
        print(f"RESULT: EXCELLENT AGREEMENT — {overall_pct:.2f}% match rate.")
    elif overall_pct >= 95.0:
        print(f"RESULT: GOOD AGREEMENT — {overall_pct:.2f}% match rate.")
    else:
        print(f"RESULT: NEEDS INVESTIGATION — {overall_pct:.2f}% match rate.")

    return 0 if overall_pct >= 99.0 else 1


if __name__ == "__main__":
    sys.exit(main())
