"""Import Ghidra function names and string labels into Binary Ninja.

Runnable as a BN plugin command or standalone from the command line.
Does NOT modify the original Ghidra project — reads only from TSV exports.
"""

import csv
import re
import sys

# No default paths — callers must provide explicit paths.
_DEFAULT_FUNCTIONS_TSV = None
_DEFAULT_STRINGS_TSV = None

# Pattern matching Ghidra auto-generated function names: FUN_XXXXXXXX
_AUTO_NAME_RE = re.compile(r'^FUN_[0-9a-fA-F]{8}$')


def _parse_functions_tsv(tsv_path: str, skip_auto_names: bool = True):
    """Yield (address: int, name: str, size: int) from the Ghidra functions TSV.

    Columns expected: address, name, size, calling_convention
    """
    with open(tsv_path, 'r', newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            name = row['name'].strip()
            if skip_auto_names and _AUTO_NAME_RE.match(name):
                continue
            addr = int(row['address'], 16)
            size = int(row['size'])
            yield addr, name, size


def _parse_strings_tsv(tsv_path: str):
    """Yield (address: int, text: str, xrefs: list[int]) from the strings TSV.

    Columns expected: string_address, string_text, ref_from_addresses
    """
    with open(tsv_path, 'r', newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            addr = int(row['string_address'], 16)
            text = row['string_text'].strip()
            refs_str = row.get('ref_from_addresses', '').strip()
            xrefs = []
            if refs_str:
                for ref in refs_str.split(','):
                    ref = ref.strip()
                    if ref:
                        xrefs.append(int(ref, 16))
            yield addr, text, xrefs


def import_ghidra_functions(bv, tsv_path: str | None = None,
                            skip_auto_names: bool = True) -> int:
    """Import function names from Ghidra TSV export. Returns count imported."""
    if tsv_path is None:
        raise ValueError('tsv_path is required — no default path configured')
    count = 0
    for addr, name, size in _parse_functions_tsv(tsv_path, skip_auto_names):
        # Create or get the function at this address
        func = bv.get_function_at(addr)
        if func is None:
            bv.create_user_function(addr)
            func = bv.get_function_at(addr)
        if func is not None:
            func.name = name
            count += 1
    return count


def import_ghidra_strings(bv, tsv_path: str | None = None) -> int:
    """Import string cross-references from Ghidra TSV export. Returns count imported."""
    if tsv_path is None:
        raise ValueError('tsv_path is required — no default path configured')
    from binaryninja import Type

    count = 0
    for addr, text, _xrefs in _parse_strings_tsv(tsv_path):
        # Define a data variable for the string at this address
        str_len = len(text.encode('utf-8')) + 1  # include null terminator
        bv.define_user_data_var(addr, Type.array(Type.char(), str_len))
        # Set a descriptive symbol name
        sanitized = re.sub(r'[^A-Za-z0-9_]', '_', text)[:64]
        if sanitized:
            bv.define_user_symbol(
                bv.get_symbol_at(addr)
                or _make_symbol(addr, f'str_{sanitized}')
            )
            # Fallback: use set_comment if symbol creation is awkward
            bv.set_comment_at(addr, text)
        count += 1
    return count


def _make_symbol(addr: int, name: str):
    """Create a DataSymbol at the given address."""
    from binaryninja import Symbol, SymbolType
    return Symbol(SymbolType.DataSymbol, addr, name)


def _plugin_import_functions(bv):
    """BN plugin command callback: import Ghidra function names."""
    from binaryninja import get_open_filename_input, log_info, log_error
    path = get_open_filename_input('Select Ghidra functions.tsv', '*.tsv')
    if not path:
        return
    try:
        count = import_ghidra_functions(bv, path)
        log_info(f'SuperBiHnja: imported {count} function names from Ghidra')
    except Exception as e:
        log_error(f'SuperBiHnja: failed to import functions: {e}')


def _plugin_import_strings(bv):
    """BN plugin command callback: import Ghidra string labels."""
    from binaryninja import get_open_filename_input, log_info, log_error
    path = get_open_filename_input('Select Ghidra strings TSV', '*.tsv')
    if not path:
        return
    try:
        count = import_ghidra_strings(bv, path)
        log_info(f'SuperBiHnja: imported {count} string labels from Ghidra')
    except Exception as e:
        log_error(f'SuperBiHnja: failed to import strings: {e}')


# Register as Binary Ninja plugin commands (only when BN is available)
try:
    from binaryninja import PluginCommand
    PluginCommand.register(
        'Import Ghidra Functions',
        'Import function names from Ghidra TSV export',
        _plugin_import_functions,
    )
    PluginCommand.register(
        'Import Ghidra Strings',
        'Import string cross-reference labels from Ghidra TSV export',
        _plugin_import_strings,
    )
except ImportError:
    pass  # Running outside Binary Ninja


# ── CLI entry point ──────────────────────────────────────────────────────
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Preview Ghidra→Binary Ninja function/string import',
    )
    parser.add_argument(
        'functions_tsv',
        help='Path to Ghidra functions.tsv',
    )
    parser.add_argument(
        'strings_tsv',
        help='Path to Ghidra net_strings_xrefs.tsv',
    )
    parser.add_argument(
        '--include-auto', action='store_true',
        help='Include FUN_XXXXXXXX auto-generated names',
    )
    args = parser.parse_args()

    # Functions summary
    funcs = list(_parse_functions_tsv(args.functions_tsv,
                                      skip_auto_names=not args.include_auto))
    print(f'Functions TSV: {args.functions_tsv}')
    print(f'  Total entries (after filter): {len(funcs)}')
    if funcs:
        print(f'  First 10:')
        for addr, name, size in funcs[:10]:
            print(f'    0x{addr:08x}  {name:40s}  ({size} bytes)')

    # Strings summary
    strings = list(_parse_strings_tsv(args.strings_tsv))
    print(f'\nStrings TSV: {args.strings_tsv}')
    print(f'  Total entries: {len(strings)}')
    if strings:
        print(f'  First 10:')
        for addr, text, xrefs in strings[:10]:
            xref_str = f'  xrefs: {len(xrefs)}' if xrefs else ''
            print(f'    0x{addr:08x}  {text[:50]:50s}{xref_str}')
