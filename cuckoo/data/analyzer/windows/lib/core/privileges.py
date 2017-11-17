# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from ctypes import wintypes, POINTER

from lib.common.defines import ADVAPI32, KERNEL32, SE_PRIVILEGE_ENABLED
from lib.common.defines import LUID, TOKEN_PRIVILEGES
from lib.common.defines import TOKEN_ALL_ACCESS, LUID_AND_ATTRIBUTES

def grant_privilege(privilege):
    """Grant debug privileges.
    @param pid: PID.
    @return: operation status.
    """
    ADVAPI32.OpenProcessToken.argtypes = (wintypes.HANDLE,
                                          wintypes.DWORD,
                                          POINTER(wintypes.HANDLE))

    ADVAPI32.LookupPrivilegeValueW.argtypes = (wintypes.LPWSTR,
                                               wintypes.LPWSTR,
                                               POINTER(LUID))

    ADVAPI32.AdjustTokenPrivileges.argtypes = (wintypes.HANDLE,
                                               wintypes.BOOL,
                                               POINTER(TOKEN_PRIVILEGES),
                                               wintypes.DWORD,
                                               POINTER(TOKEN_PRIVILEGES),
                                               POINTER(wintypes.DWORD))

    h_process = KERNEL32.GetCurrentProcess()

    h_current_token = wintypes.HANDLE()
    if not ADVAPI32.OpenProcessToken(h_process,
                                     TOKEN_ALL_ACCESS,
                                     h_current_token):
        return False

    se_original_luid = LUID()
    if not ADVAPI32.LookupPrivilegeValueW(None, privilege, se_original_luid):
        return False

    luid_attributes = LUID_AND_ATTRIBUTES()
    luid_attributes.Luid = se_original_luid
    luid_attributes.Attributes = SE_PRIVILEGE_ENABLED
    token_privs = TOKEN_PRIVILEGES()
    token_privs.PrivilegeCount = 1
    token_privs.Privileges = luid_attributes

    if not ADVAPI32.AdjustTokenPrivileges(h_current_token, False, token_privs,
                                          0, None, None):
        return False

    KERNEL32.CloseHandle(h_current_token)
    KERNEL32.CloseHandle(h_process)
    return True
