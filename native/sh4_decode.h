#pragma once
#include "sh4.h"

/* Decode a single SH-4 instruction from little-endian bytes.
   Returns false only when len < 2.  On success, `out` is fully populated
   (defaults to DOT_WORD with the raw halfword as an IMM operand when the
   encoding is unrecognised). */
bool sh4_decode(const uint8_t* data, size_t len, uint32_t addr, SH4Instruction& out);

/* Return the canonical mnemonic string for a Mnemonic enum value.
   Never returns nullptr (returns ".word" for UNKNOWN / out-of-range). */
const char* sh4_mnemonic_name(Mnemonic mn);
