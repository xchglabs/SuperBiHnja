# SuperBiHnja — SH-4 Architecture Plugin for Binary Ninja

SH-4 (SH7750 family, little-endian, 32-bit) architecture plugin for Binary Ninja.
Works with any SH-4 little-endian target.

## Installation

### Native C++ plugin (recommended)

The native plugin provides dramatically faster decode, disassembly text, and IL lifting — the difference between a usable and unusable experience on large firmware.

```bash
git clone https://github.com/xchglabs/SuperBiHnja.git
cd SuperBiHnja

# Clone BN API headers matching your installed build
git clone https://github.com/Vector35/binaryninja-api /tmp/bn-api
git -C /tmp/bn-api checkout $(cat /path/to/binaryninja/api_REVISION.txt)

# Build
mkdir -p native/build && cd native/build
cmake -DBN_API_PATH=/tmp/bn-api -DBN_INSTALL_DIR=/path/to/binaryninja ..
make -j$(nproc)

# Install
ln -s "$(pwd)/libarch_sh4.so" ~/.binaryninja/plugins/libarch_sh4.so
```

### Python plugin (BinaryView + Ghidra import)

The Python plugin provides the raw-firmware BinaryView, settings, and Ghidra import command. It auto-detects the native C++ plugin and skips Python architecture registration when it is present.

```bash
ln -s "$(cd SuperBiHnja && pwd)/superbiHnja" ~/.binaryninja/plugins/superbiHnja
```

Both symlinks are needed for full functionality. Requires Binary Ninja with Python API access.

## Usage

**Raw firmware (`.bin`)**
Open the binary, then select `SH4-Firmware` from the view type dropdown. Configure the base address via Settings → SuperBiHnja → SH-4 Firmware Base Address (default `0x00000000`).

**ELF**
Open any SH-4 ELF (`EM_SH`, machine type 42) — auto-selects `sh4` architecture via ELF loader registration.

**Ghidra function import**
`Plugins → Import Ghidra Functions` — imports function names and boundaries from a Ghidra-exported `functions.tsv`.

## Components

### Native C++ plugin (`native/`)

| File | Purpose |
|---|---|
| `sh4.h` | Shared types — registers, flags, mnemonics, instruction struct |
| `sh4_decode.cpp` | Instruction decoder — 120+ mnemonics, full SH-4 ISA |
| `sh4_lift.cpp` | LLIL lifter — all mnemonics, delay slot sequencing, T-flag semantics |
| `sh4_arch.cpp` | Architecture class, calling convention, `CorePluginInit` |
| `CMakeLists.txt` | Build config linking against BN API |

### Python plugin (`superbiHnja/`)

| File | Purpose |
|---|---|
| `sh4_decode.py` | Python decoder (fallback when native plugin absent) |
| `sh4_lift.py` | Python LLIL lifter (fallback) |
| `sh4_arch.py` | Python architecture registration (fallback) |
| `sh4_binaryview.py` | Raw firmware BinaryView — segment mapping, entry point |
| `sh4_calling_convention.py` | SH-4 ABI — r4-r7 int args, fr4-fr7 float args, r0 return |
| `ghidra_import.py` | Ghidra TSV import plugin |
| `sh4_types.py` | Shared types — register enums, operand classes, instruction containers |

## Supported ISA

Full SH-4 (SH7750) little-endian instruction set:

- **Integer**: arithmetic (add/sub/addv/subv/addc/subc/neg/negc/dt), logical (and/or/xor/not/tst), shifts (shl/shr/sha/rot/rotc), multiply/MAC, compare, extend, swap, xtrct
- **Branch**: unconditional (bra/bsr/jmp/jsr), conditional (bt/bf/bt.s/bf.s), return (rts/rte) — all with correct delay slot handling
- **System**: privileged (ldc/stc/ldtlb), status register (sts/lds for MACH/MACL/PR/FPUL/FPSCR), TAS, CLRMAC, CLRS, SETS, TRAPA, SLEEP
- **FPU**: single and double precision — fmov, fadd, fsub, fmul, fdiv, fsqrt, fcmp, float, ftrc, fabs, fneg, fldi0/1, flds/fsts, fcnvsd/fcnvds, frchg/fschg

## Known Limitations

- `fipr`, `ftrv`, `fsrra`, `fsca`, `sleep` decode correctly but have no LLIL semantics (lifted as unimplemented)
- Raw firmware base address configured via BN Settings (`superbiHnja.firmware.baseAddress`); default is `0x00000000`
- Calling convention assumes standard SH-4 ABI (r4-r7 int args, fr4-fr7 float args, r0 return)
- Full-binary analysis on large firmware (>10 MB) can take several minutes in Binary Ninja

## Validation

**Decoder tests** — 15 tests covering instruction encoding, operand parsing, capstone agreement, and function boundary detection:
```bash
python3 -m pytest superbiHnja/tests/test_decode.py -v
```

**Ghidra cross-validation** — compares decoder output against 170 Ghidra-disassembled functions (53,525 instructions):
```bash
python3 scripts/validate_ghidra.py
```
Result: **99.89% mnemonic agreement** (53,468/53,525). All 57 mismatches are `fmov.s` (Ghidra) vs `fmov` (decoder) — a naming convention difference for single-precision FMOV, not a semantic disagreement.

**Smoke test** — headless BinaryView creation, segment mapping, ELF loading, and LLIL generation:
```bash
python3 scripts/smoke_test.py
```

## Environment Variables

Dev/validation scripts require these environment variables (no defaults — scripts fail if unset). These are **not** used by the plugin itself.

| Variable | Used by | Description |
|---|---|---|
| `SH4_FIRMWARE_BIN` | tests, smoke_test, validate_ghidra | Path to raw firmware `.bin` |
| `SH4_FIRMWARE_ELF` | smoke_test | Path to elf |
| `SH4_FUNCTIONS_TSV` | tests | Path to Ghidra `functions.tsv` export |
| `SH4_GHIDRA_ASM_DIR` | validate_ghidra | Directory of Ghidra `.asm` exports |
| `SH4_FIRMWARE_BASE` | smoke_test | Firmware base address (hex, e.g. `0x08000000`) |
| `SH4_KNOWN_FUNC` | smoke_test | Address of a known function to verify LLIL (hex) |

## License

Apache-2.0 — see [LICENSE](LICENSE).
