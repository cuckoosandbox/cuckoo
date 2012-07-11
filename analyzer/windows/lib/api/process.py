# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import string
import random
import logging
from time import time
from ctypes import *
from shutil import copy

from lib.common.defines import *
from lib.common.paths import PATHS
from lib.core.errors import get_error_string

log = logging.getLogger(__name__)

def randomize_dll(dll_path):
    """Randomize DLL name.
    @return: new DLL path.
    """
    new_dll_name = "".join(random.choice(string.ascii_letters) for x in range(6))
    new_dll_path = os.path.join("dll", "%s.dll" % new_dll_name)

    try:
        copy(dll_path, new_dll_path)
        return new_dll_path
    except:
        return dll_path

class Process:
    """Windows process."""

    def __init__(self, pid=0, h_process=0, thread_id=0, h_thread=0):
        """@param pid: PID.
        @param h_process: process handle.
        @param thread_id: thread id.
        @param h_thread: thread handle.
        """
        self.pid = pid
        self.h_process = h_process
        self.thread_id = thread_id
        self.h_thread = h_thread
        self.suspended = False

    def get_system_info(self):
        """Get system information."""
        self.system_info = SYSTEM_INFO()
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open(self):
        """Open a process.
        @return: operation status.
        """
        if self.pid == 0:
            return False

        self.h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                              False,
                                              int(self.pid))
        return True

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        if not self.h_process:
            self.open()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(self.h_process, byref(exit_code))

        return exit_code.value

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        if self.exit_code() == STILL_ACTIVE:
            return True
        else:
            return False

    def execute(self, path=None, args=None, suspended=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param suspended: is suspended.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            return False

        startup_info = STARTUPINFO()
        startup_info.cb = sizeof(startup_info)
        process_info = PROCESS_INFORMATION()

        if args:
            arguments = "\"" + path + "\" " + args
        else:
            arguments = None

        creation_flags = CREATE_NEW_CONSOLE
        if suspended:
            self.suspended = True
            creation_flags += CREATE_SUSPENDED

        created = KERNEL32.CreateProcessA(path,
                                          arguments,
                                          None,
                                          None,
                                          None,
                                          creation_flags,
                                          None,
                                          None,
                                          byref(startup_info),
                                          byref(process_info))

        if created:
            self.pid = process_info.dwProcessId
            self.h_thread = process_info.hThread
            log.info("Successfully executed process from path \"%s\" with arguments \"%s\" with pid %d"
                     % (path, args, self.pid))
            return True
        else:
            log.error("Failed to execute process from path \"%s\" with arguments \"%s\"" % (path, args))
            return False

    def resume(self):
        """Resume a suspended thread.
        @return: operation status.
        """
        if not self.suspended:
            log.warning("The process with pid %d was not suspended at creation" % self.pid)
            return False

        if self.h_thread == 0:
            return False

        KERNEL32.Sleep(2000)

        if KERNEL32.ResumeThread(self.h_thread):
            log.info("Successfully resumed process with pid %d" % self.pid)
            return True
        else:
            log.error("Failed to resume process with pid %d" % self.pid)
            return False

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        if self.h_process == 0:
            self.open()

        if KERNEL32.TerminateProcess(self.h_process, 1):
            log.info("Successfully terminated process with pid %d" % self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d" % self.pid)
            return False

    def inject(self, dll=os.path.join("dll", "cuckoomon.dll"), apc=False):
        """Cuckoo DLL injection.
        @param dll: Cuckoo DLL path.
        @param apc: APC use.
        """
        if self.pid == 0:
            log.warning("No valid pid specified, injection aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %d is not alive, injection aborted" % self.pid)
            return False

        dll = randomize_dll(dll)

        if not dll or not os.path.exists(dll):
            log.warning("No valid DLL specified to be injected in process with pid %d, injection aborted" % self.pid)
            return False

        KERNEL32.Sleep(2000)

        arg = KERNEL32.VirtualAllocEx(self.h_process,
                                      0,
                                      len(dll),
                                      MEM_RESERVE | MEM_COMMIT,
                                      PAGE_READWRITE)

        if not arg:
            log.error("VirtualAllocEx failed when injecting process with pid %d, injection aborted (Error: %s)"
                      % (self.pid, get_error_string(KERNEL32.GetLastError())))
            return False

        bytes_written = c_int(0)
        if not KERNEL32.WriteProcessMemory(self.h_process,
                                           arg,
                                           dll,
                                           len(dll),
                                           byref(bytes_written)):
            log.error("WriteProcessMemory failed when injecting process with pid %d, injection aborted (Error: %s)"
                      % (self.pid, get_error_string(KERNEL32.GetLastError())))
            return False

        kernel32_handle = KERNEL32.GetModuleHandleA("kernel32.dll")
        load_library = KERNEL32.GetProcAddress(kernel32_handle,
                                               "LoadLibraryA")

        if apc or self.suspended:
            log.info("Using QueueUserAPC injection")
            if self.h_thread == 0:
                log.info("No valid thread handle specified for injecting process with pid %d, injection aborted" % self.pid)
                return False
            
            if KERNEL32.QueueUserAPC(load_library, self.h_thread, arg) == 0:
                log.error("QueueUserAPC failed when injecting process with pid %d (Error: %s)"
                          % (self.pid, get_error_string(KERNEL32.GetLastError())))
                return False
        else:
            log.info("Using CreateRemoteThread injection")
            new_thread_id = c_ulong(0)
            if not KERNEL32.CreateRemoteThread(self.h_process,
                                               None,
                                               0,
                                               load_library,
                                               arg,
                                               0,
                                               byref(new_thread_id)):
                log.error("CreateRemoteThread failed when injecting process with pid %d (Error: %s)"
                          % (self.pid, get_error_string(KERNEL32.GetLastError())))
                return False

        log.info("Successfully injected process with pid %d" % self.pid)

        return True

    def dump_memory(self):
        """Dump process memory.
        @return: operation status.
        """
        if self.pid == 0:
            log.warning("No valid pid specified, memory dump aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %d is not alive, memory dump aborted" % self.pid)
            return False

        self.get_system_info()

        page_size = self.system_info.dwPageSize
        min_addr = self.system_info.lpMinimumApplicationAddress
        max_addr = self.system_info.lpMaximumApplicationAddress
        mem = min_addr

        root = os.path.join(PATHS["memory"], str(self.pid))
        root = os.path.join(root, str(int(time())))

        if not os.path.exists(root):
            os.makedirs(root)

        while(mem < max_addr):
            mbi = MEMORY_BASIC_INFORMATION()
            count = c_ulong(0)

            if KERNEL32.VirtualQueryEx(self.h_process, mem, byref(mbi), sizeof(mbi)) < sizeof(mbi):
                mem += page_size
                continue

            if mbi.State == 0x1000 and mbi.Type == 0x20000:
                buf = create_string_buffer(mbi.RegionSize)
                if KERNEL32.ReadProcessMemory(self.h_process,
                                              mem,
                                              buf,
                                              mbi.RegionSize,
                                              byref(count)):
                    path = os.path.join(root, "0x%.8x.dmp" % mem)
                    chunk = open(path, "wb")
                    chunk.write(buf.raw)
                    chunk.close()
                mem += mbi.RegionSize
            else:
                mem += page_size

        log.info("Memory dump of process with pid %d completed" % self.pid)

        return True
