# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes

class Structure(ctypes.Structure):
    def as_dict(self):
        ret = {}
        for field, _ in self._fields_:
            value = getattr(self, field)
            if isinstance(value, Structure):
                ret[field] = value.as_dict()
            elif hasattr(value, "value"):
                ret[field] = value
            elif hasattr(value, "__getitem__"):
                ret[field] = value[:]
            else:
                ret[field] = value
        return ret

class LnkHeader(Structure):
    _fields_ = [
        ("signature", ctypes.c_ubyte * 4),
        ("guid", ctypes.c_ubyte * 16),
        ("flags", ctypes.c_uint),
        ("attrs", ctypes.c_uint),
        ("creation", ctypes.c_ulonglong),
        ("access", ctypes.c_ulonglong),
        ("modified", ctypes.c_ulonglong),
        ("target_len", ctypes.c_uint),
        ("icon_len", ctypes.c_uint),
        ("show_window", ctypes.c_uint),
        ("hotkey", ctypes.c_uint),
    ]

class LnkEntry(Structure):
    _fields_ = [
        ("length", ctypes.c_uint),
        ("first_offset", ctypes.c_uint),
        ("volume_flags", ctypes.c_uint),
        ("local_volume", ctypes.c_uint),
        ("base_path", ctypes.c_uint),
        ("net_volume", ctypes.c_uint),
        ("path_remainder", ctypes.c_uint),
    ]

class PUBLICKEYSTRUC(Structure):
    _pack_ = 1
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("version", ctypes.c_ubyte),
        ("reserved", ctypes.c_ushort),
        ("algid", ctypes.c_uint),
    ]

class RSAPUBKEY(Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint),
        ("bitlen", ctypes.c_uint),
        ("pubexp", ctypes.c_uint),
    ]
