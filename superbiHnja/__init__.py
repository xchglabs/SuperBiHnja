"""SuperBiHnja — SH-4 architecture plugin for Binary Ninja."""

import binaryninja
from binaryninja import Settings

from .sh4_binaryview import SH4FirmwareView

# The native C++ plugin (libarch_sh4.so) registers the sh4 architecture,
# calling convention, and ELF mapping.  Only fall back to the Python
# architecture if the native plugin is absent.
try:
    arch = binaryninja.Architecture['sh4']
except Exception:
    # Native plugin not loaded — register the Python architecture.
    from .sh4_arch import SH4Architecture
    from .sh4_calling_convention import SH4CallingConvention

    SH4Architecture.register()
    arch = binaryninja.Architecture['sh4']
    cc = SH4CallingConvention(arch, 'sh4-default')
    arch.register_calling_convention(cc)
    arch.standalone_platform.default_calling_convention = cc

    from binaryninja import BinaryViewType, Endianness
    BinaryViewType['ELF'].register_arch(42, Endianness.LittleEndian, arch)

# Stack-based calling convention for variadic logger/assert helpers (args on
# the stack, not r4-r7). The native plugin registers 'sh4-stack' itself; add
# it here when it is absent (Python arch, or an older native build).
if 'sh4-stack' not in arch.calling_conventions:
    from .sh4_calling_convention import SH4StackCallingConvention
    arch.register_calling_convention(SH4StackCallingConvention(arch, 'sh4-stack'))

# Register firmware base-address setting
settings = Settings()
settings.register_group('superbiHnja', 'SuperBiHnja')
settings.register_setting('superbiHnja.firmware.baseAddress', '{"title": "SH-4 Firmware Base Address", "description": "Base address for loading raw SH-4 firmware images", "type": "string", "default": "0x00000000"}')
settings.register_setting('superbiHnja.firmware.recoverStrings', '{"title": "Recover String Xrefs", "description": "After analysis, detect literal-pool strings and create their cross-references. SH-4 loads every string address from a PC-relative pool that BN does not turn into an xref on its own.", "type": "boolean", "default": true}')
settings.register_setting('superbiHnja.firmware.mapMirrors', '{"title": "Map P1/P2 Address Mirrors", "description": "Map the SH cached (0x8xxxxxxx) and uncached (0xAxxxxxxx) mirror windows over the same image bytes, so pointers stored in a mirror window (e.g. __FILE__ assert strings via 0xA8xxxxxx) resolve to their targets and get cross-references.", "type": "boolean", "default": true}')

# Register the raw-firmware BinaryView
SH4FirmwareView.register()

# Register the on-demand string-xref recovery command (also covers ELF loads)
from .sh4_strings import register_plugin_command
register_plugin_command()
