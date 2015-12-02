# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from ctypes import windll, POINTER, byref, Structure, pointer
from ctypes import c_ushort, c_wchar_p, c_void_p, create_string_buffer
from ctypes.wintypes import HANDLE, DWORD, LPCWSTR, ULONG, LONG
from _winreg import KEY_ALL_ACCESS, KEY_QUERY_VALUE, KEY_SET_VALUE
from _winreg import REG_SZ, REG_MULTI_SZ

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

RegQueryValueExW = windll.advapi32.RegQueryValueExW
RegQueryValueExW.argtypes = \
    HANDLE, LPCWSTR, POINTER(DWORD), POINTER(DWORD), c_void_p, POINTER(DWORD)
RegQueryValueExW.restype = LONG

RegSetValueExW = windll.advapi32.RegSetValueExW
RegSetValueExW.argtypes = HANDLE, LPCWSTR, DWORD, DWORD, c_void_p, DWORD
RegSetValueExW.restype = LONG

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
    res = RegOpenKeyExW(rootkey, subkey, 0, KEY_QUERY_VALUE, byref(res_handle))
    RegCloseKey(res_handle)
    return not res

def set_regkey(rootkey, subkey, name, type_, value):
    if type_ == REG_SZ:
        value = unicode(value)
    if type_ == REG_MULTI_SZ:
        value = u"\u0000".join(value) + u"\u0000\u0000"

    res_handle = HANDLE()
    res = RegOpenKeyExW(rootkey, subkey, 0, KEY_SET_VALUE, byref(res_handle))
    if not res:
        RegSetValueExW(res_handle, name, 0, type_, value, len(value))
        RegCloseKey(res_handle)

def query_value(rootkey, subkey, name):
    res_handle = HANDLE()
    type_ = DWORD()
    value = create_string_buffer(1024 * 1024)
    length = DWORD(1024 * 1024)

    res = RegOpenKeyExW(rootkey, subkey, 0, KEY_QUERY_VALUE, byref(res_handle))
    if not res:
        res = RegQueryValueExW(res_handle, name, None, byref(type_), value, byref(length))
        RegCloseKey(res_handle)

    if not res:
        if type_.value == REG_SZ:
            return value.raw[:length.value].decode("utf16").rstrip("\x00")
        if type_.value == REG_MULTI_SZ:
            value = value.raw[:length.value].decode("utf16")
            return value.rstrip(u"\u0000").split(u"\u0000")
        return value.raw[:length.value]
