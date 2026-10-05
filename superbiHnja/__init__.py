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

# Register firmware base-address setting
settings = Settings()
settings.register_group('superbiHnja', 'SuperBiHnja')
settings.register_setting('superbiHnja.firmware.baseAddress', '{"title": "SH-4 Firmware Base Address", "description": "Base address for loading raw SH-4 firmware images", "type": "string", "default": "0x00000000"}')

# Register the raw-firmware BinaryView
SH4FirmwareView.register()
