# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes as c

from cuckoo.misc import Structure

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5

class PUBLICKEYSTRUC(Structure):
    _pack_ = 1
    _fields_ = [
        ("type", c.c_ubyte),
        ("version", c.c_ubyte),
        ("reserved", c.c_ushort),
        ("algid", c.c_uint),
    ]

class RSAPUBKEY(Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", c.c_uint),
        ("bitlen", c.c_uint),
        ("pubexp", c.c_uint),
    ]
