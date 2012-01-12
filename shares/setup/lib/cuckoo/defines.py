# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

from ctypes import *

# The following definitions were taken from PyBox:
# http://code.google.com/p/pyboxed
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LONG      = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong
HMODULE   = c_ulong
NULL = c_int(0)

# Constants
DEBUG_PROCESS             = 0x00000001
CREATE_NEW_CONSOLE        = 0x00000010
CREATE_SUSPENDED          = 0x00000004
DBG_CONTINUE              = 0x00010002
INFINITE                  = 0xFFFFFFFF
PROCESS_ALL_ACCESS        = 0x001F0FFF
TOKEN_ALL_ACCESS          = 0x000F01FF
SE_PRIVILEGE_ENABLED      = 0x00000002

# Memory permissions
PAGE_EXECUTE_READWRITE    = 0x00000040
PAGE_EXECUTE              = 0x00000010
PAGE_EXECUTE_READ         = 0x00000020
PAGE_READONLY             = 0x00000002
PAGE_READWRITE            = 0x00000004

# Memory Allocation Type
MEM_COMMIT                = 0x00001000
MEM_RESERVE               = 0x00002000
MEM_DECOMMIT              = 0x00004000
MEM_RELEASE               = 0x00008000
MEM_RESET                 = 0x00080000

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS             = 0x00000001
PAGE_READONLY             = 0x00000002
PAGE_READWRITE            = 0x00000004
PAGE_WRITECOPY            = 0x00000008
PAGE_EXECUTE              = 0x00000010
PAGE_EXECUTE_READ         = 0x00000020
PAGE_EXECUTE_READWRITE    = 0x00000040
PAGE_EXECUTE_WRITECOPY    = 0x00000080
PAGE_GUARD                = 0x00000100
PAGE_NOCACHE              = 0x00000200
PAGE_WRITECOMBINE         = 0x00000400

class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]

class LUID(Structure):
    _fields_ = [
        ('LowPart', DWORD),
        ('HighPart', LONG),
        ]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', DWORD),
        ]
    
class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ('PrivilegeCount', DWORD),
        ('Privileges', LUID_AND_ATTRIBUTES),
        ]

# MEMORY_BASIC_INFORMATION contains information about a 
# particular region of memory. A call to kernel32.VirtualQuery()
# populates this structure.
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
]

########################################################################
# Following are extended values for Cuckoo execution.
########################################################################

# Pipe server constants.
PIPE_ACCESS_DUPLEX          = 0x00000003
PIPE_TYPE_MESSAGE           = 0x00000004
PIPE_READMODE_MESSAGE       = 0x00000002
PIPE_WAIT                   = 0x00000000
PIPE_UNLIMITED_INSTANCES    = 0x000000ff
INVALID_HANDLE_VALUE        = 0xffffffff
ERROR_BROKEN_PIPE           = 0x0000006d
# Process constants.
STILL_ACTIVE                = 0x00000103

KERNEL32 = windll.kernel32
ADVAPI32 = windll.advapi32
