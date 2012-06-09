# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from ctypes import sizeof, byref, c_int, c_ulong, wintypes
import ctypes

from lib.common.defines import *

def grant_debug_privilege(pid=0):
    """Grant debug privileges.
    @param pid: PID.
    @return: operation status.
    """
    ADVAPI32.OpenProcessToken.argtypes = (wintypes.HANDLE,
                                          wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE))

    ADVAPI32.LookupPrivilegeValueW.argtypes = (wintypes.LPWSTR,
                                               wintypes.LPWSTR,
                                               ctypes.POINTER(LUID))
    ADVAPI32.AdjustTokenPrivileges.argtypes = (wintypes.HANDLE,
                                               wintypes.BOOL,
                                               ctypes.POINTER(TOKEN_PRIVILEGES),
                                               wintypes.DWORD,
                                               ctypes.POINTER(TOKEN_PRIVILEGES),
                                               ctypes.POINTER(wintypes.DWORD))

    h_process = None
    if pid == 0:
        h_process = KERNEL32.GetCurrentProcess()
    else:
        h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                         False,
                                         pid)

    if not h_process:
        return False    

    h_current_token = wintypes.HANDLE() 
    if not ADVAPI32.OpenProcessToken(h_process,
                                     TOKEN_ALL_ACCESS,
                                     h_current_token):
        return False
    
    se_original_luid = LUID()
    if not ADVAPI32.LookupPrivilegeValueW(None,
                                          "SeDebugPrivilege",
                                          se_original_luid):
        return False

    luid_attributes = LUID_AND_ATTRIBUTES()
    luid_attributes.Luid = se_original_luid
    luid_attributes.Attributes = SE_PRIVILEGE_ENABLED
    token_privs = TOKEN_PRIVILEGES()
    token_privs.PrivilegeCount = 1;
    token_privs.Privileges = luid_attributes; 
    
    if not ADVAPI32.AdjustTokenPrivileges(h_current_token,
                                          False,
                                          token_privs,
                                          0,
                                          None,
                                          None):
        return False
    
    KERNEL32.CloseHandle(h_current_token)
    KERNEL32.CloseHandle(h_process)

    return True
