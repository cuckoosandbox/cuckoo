# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from ctypes import windll, POINTER, byref, Structure, pointer
from ctypes import c_ushort, c_wchar_p
from ctypes.wintypes import HANDLE, DWORD, LPCWSTR, ULONG, LONG
from _winreg import KEY_ALL_ACCESS

log = logging.getLogger(__name__)

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", c_ushort),
        ("MaximumLength", c_ushort),
        ("Buffer", c_wchar_p),
    ]

RegOpenKeyExW = windll.advapi32.RegOpenKeyExW
RegOpenKeyExW.argtypes = HANDLE, LPCWSTR, DWORD, ULONG, POINTER(HANDLE)
RegOpenKeyExW.restype = LONG

NtRenameKey = windll.ntdll.NtRenameKey
NtRenameKey.argtypes = HANDLE, POINTER(UNICODE_STRING)

RegCloseKey = windll.advapi32.RegCloseKey
RegCloseKey.argtypes = HANDLE,

def rename_regkey(skey, ssubkey, dsubkey):
    """Rename an entire tree of values in the registry.
    Function by Thorsten Sick."""
    res_handle = HANDLE()
    options = DWORD(0)
    res = RegOpenKeyExW(skey, ssubkey, options,
                        KEY_ALL_ACCESS, byref(res_handle))
    if not res:
        bsize = c_ushort(len(dsubkey) * 2)
        us = UNICODE_STRING()
        us.Buffer = c_wchar_p(dsubkey)
        us.Length = bsize
        us.MaximumLength = bsize

        res = NtRenameKey(res_handle, pointer(us))
        if res:
            log.warning("Error renaming %s\\%s to %s (0x%x)",
                        skey, ssubkey, dsubkey, res % 2**32)

    if res_handle:
        RegCloseKey(res_handle)

def regkey_exists(rootkey, subkey):
    res_handle = HANDLE()
    res = RegOpenKeyExW(rootkey, subkey, 0, KEY_ALL_ACCESS, byref(res_handle))
    RegCloseKey(res_handle)
    return not res
