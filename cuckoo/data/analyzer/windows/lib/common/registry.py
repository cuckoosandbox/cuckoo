# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import _winreg

from ctypes import windll, POINTER, byref, Structure, pointer
from ctypes import c_ushort, c_wchar_p, c_void_p, create_string_buffer
from ctypes.wintypes import HANDLE, DWORD, LPCWSTR, ULONG, LONG

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

RegCreateKeyExW = windll.advapi32.RegCreateKeyExW
RegCreateKeyExW.argtypes = (
    HANDLE, LPCWSTR, DWORD, LPCWSTR, DWORD, DWORD,
    DWORD, POINTER(HANDLE), POINTER(DWORD),
)
RegCreateKeyExW.restype = LONG

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

_rootkeys = {
    "HKEY_LOCAL_MACHINE": _winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER": _winreg.HKEY_CURRENT_USER,
}

_regtypes = {
    "REG_DWORD": _winreg.REG_DWORD,
    "REG_SZ": _winreg.REG_SZ,
    "REG_BINARY": _winreg.REG_BINARY,
}

def rename_regkey(skey, ssubkey, dsubkey):
    """Rename an entire tree of values in the registry.
    Function by Thorsten Sick."""
    res_handle = HANDLE()
    options = DWORD(0)
    res = RegOpenKeyExW(
        skey, ssubkey, options, _winreg.KEY_ALL_ACCESS, byref(res_handle)
    )
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
    res = RegOpenKeyExW(
        rootkey, subkey, 0, _winreg.KEY_QUERY_VALUE, byref(res_handle)
    )
    RegCloseKey(res_handle)
    return not res

def set_regkey(rootkey, subkey, name, type_, value):
    if type_ == _winreg.REG_SZ:
        value = unicode(value)
    if type_ == _winreg.REG_MULTI_SZ:
        value = u"\u0000".join(value) + u"\u0000\u0000"

    res_handle = HANDLE()
    res = RegCreateKeyExW(
        rootkey, subkey, 0, None, 0, _winreg.KEY_ALL_ACCESS,
        0, byref(res_handle), None
    )
    if not res:
        RegSetValueExW(res_handle, name, 0, type_, value, len(value))
        RegCloseKey(res_handle)

def set_regkey_full(regkey, type_, value):
    components = regkey.split("\\")
    rootkey, subkey, name = components[0], components[1:-1], components[-1]
    if rootkey not in _rootkeys:
        log.warning("Unknown root key for registry key: %s", rootkey)
        return

    set_regkey(
        _rootkeys[rootkey], "\\".join(subkey), name,
        _regtypes.get(type_, type_), value
    )

def query_value(rootkey, subkey, name):
    res_handle = HANDLE()
    type_ = DWORD()
    value = create_string_buffer(1024 * 1024)
    length = DWORD(1024 * 1024)

    res = RegOpenKeyExW(
        rootkey, subkey, 0, _winreg.KEY_QUERY_VALUE, byref(res_handle)
    )
    if not res:
        res = RegQueryValueExW(
            res_handle, name, None, byref(type_), value, byref(length)
        )
        RegCloseKey(res_handle)

    if not res:
        if type_.value == _winreg.REG_SZ:
            return value.raw[:length.value].decode("utf16").rstrip("\x00")
        if type_.value == _winreg.REG_MULTI_SZ:
            value = value.raw[:length.value].decode("utf16")
            return value.rstrip(u"\u0000").split(u"\u0000")
        return value.raw[:length.value]
