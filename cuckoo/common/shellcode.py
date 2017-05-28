# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import unicorn
import unicorn.x86_const as x86

log = logging.getLogger(__name__)

archs = {
    "x86": unicorn.UC_ARCH_X86,
}

modes = {
    32: unicorn.UC_MODE_32,
}

class UcX86(unicorn.Uc):
    @property
    def esp(self):
        return self.reg_read(x86.UC_X86_REG_ESP)

    @esp.setter
    def esp(self, value):
        self.reg_write(x86.UC_X86_REG_ESP, value)

class ShellcodeX86(object):
    def __init__(self, arch, mode, sc=None):
        self.emu = UcX86(arch, mode)
        self.addr = None
        self.sc = sc
        self.init()

    def init(self):
        pass

    def map_memory(self, addr=0x1000, memsize=2*1024*1024):
        self.addr = addr
        self.emu.mem_map(addr, memsize)
        self.emu.mem_write(addr, self.sc)
        self.emu.esp = addr + memsize / 2

    def run(self, addr=None, end=0, count=None):
        try:
            self.emu.emu_start(addr or self.addr, end, count=count)
        except unicorn.UcError as e:
            log.error("Error emulating shellcode: %s", e)

class ShikataX86(ShellcodeX86):
    def init(self):
        self.bblcount = 0
        self.start = None
        self.emu.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)

    def hook_block(self, uc, addr, size, user_data):
        if not size:
            return

        self.bblcount += 1
        if self.bblcount == 2:
            self.start = addr
            return False

    def result(self):
        start = self.start or self.addr
        return self.emu.mem_read(start, len(self.sc) - start + self.addr)

def Shellcode(arch="x86", mode=32, sc=None, cls=ShellcodeX86):
    # TODO For now only 32-bit x86 shellcode is supported.
    return cls(archs[arch], modes[mode], sc)

def shikata(sc):
    s = Shellcode(sc=sc, cls=ShikataX86)
    s.map_memory()
    s.run(count=0x1000)
    return str(s.result())
