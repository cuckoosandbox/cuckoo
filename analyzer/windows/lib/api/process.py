# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import random
from time import time
from ctypes import byref, c_ulong, create_string_buffer, c_int, sizeof
from shutil import copy
import subprocess
import tempfile

from lib.common.constants import PIPE, PATHS, SHUTDOWN_MUTEX
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS
from lib.common.defines import STARTUPINFO, PROCESS_INFORMATION
from lib.common.defines import CREATE_NEW_CONSOLE, CREATE_SUSPENDED
from lib.common.defines import MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE
from lib.common.defines import MEMORY_BASIC_INFORMATION
from lib.common.defines import WAIT_TIMEOUT
from lib.common.defines import MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
from lib.common.errors import get_error_string
from lib.common.rand import random_string
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)

def randomize_dll(dll_path):
    """Randomize DLL name.
    @return: new DLL path.
    """
    new_dll_name = random_string(6)
    new_dll_path = os.path.join(os.getcwd(), "bin", "{0}.dll".format(new_dll_name))

    try:
        copy(dll_path, new_dll_path)
        return new_dll_path
    except:
        return dll_path

class Process(object):
    """Windows process."""
    first_process = True

    def __init__(self, pid=0, tid=0):
        """
        @param pid: process identifier.
        @param tid: thread identifier.
        """
        self.pid = pid
        self.tid = tid

    def get_system_info(self):
        """Get system information."""
        self.system_info = SYSTEM_INFO()
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open_process(self):
        """Open a process handle."""
        return KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)

    def open_thread(self):
        """Open a thread handle."""
        return KERNEL32.OpenThread(THREAD_ALL_ACCESS, False, self.tid)

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        process_handle = self.open_process()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(process_handle, byref(exit_code))
        KERNEL32.CloseHandle(process_handle)

        return exit_code.value

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        process_handle = self.open_process()

        NT_SUCCESS = lambda val: val >= 0

        pbi = create_string_buffer(200)
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(process_handle,
                                              27,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        KERNEL32.CloseHandle(process_handle)

        if NT_SUCCESS(ret) and size.value > 8:
            try:
                fbuf = pbi.raw[8:]
                fbuf = fbuf[:fbuf.find("\x00\x00")+1]
                return fbuf.decode("utf16", errors="ignore")
            except:
                return ""

        return ""

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        return self.exit_code() == STILL_ACTIVE

    def get_parent_pid(self):
        """Get the Parent Process ID."""
        process_handle = self.open_process()

        NT_SUCCESS = lambda val: val >= 0

        pbi = (c_int * 6)()
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(process_handle,
                                              0,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        KERNEL32.CloseHandle(process_handle)

        if NT_SUCCESS(ret) and size.value == sizeof(pbi):
            return pbi[5]

        return None

    def execute(self, path, args=None, dll=None, source=None):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param dll: dll path.
        @param source: process identifier or process name which will
                       become the parent process for the new process.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error("Unable to access file at path \"%s\", "
                      "execution aborted", path)
            return False

        if not dll:
            dll = "monitor-x86.dll"

        dll = randomize_dll(os.path.join("bin", dll))

        if not dll or not os.path.exists(dll):
            log.warning("No valid DLL specified to be injected, "
                        "injection aborted.")
            return False

        arguments = "\"" + path + "\" "
        if args:
            arguments += args

        config_path = self.drop_config()

        inject_exe = os.path.join("bin", "inject-x86.exe")
        args = [
            inject_exe, "--crt", "--dll", dll, "--app", path,
            "--config", config_path,
        ]

        if arguments:
            args += ["--cmdline", arguments]

        if source:
            if isinstance(source, (int, long)) or source.isdigit():
                args += ["--from", "%s" % source]
            else:
                args += ["--from-process", source]

        try:
            self.pid = int(subprocess.check_output(args))
        except Exception:
            log.error("Failed to execute process from path \"%s\" with "
                      "arguments \"%s\" (Error: %s)", path, args,
                      get_error_string(KERNEL32.GetLastError()))
            return False

        log.info("Successfully executed process from path \"%s\" with "
                 "arguments \"%s\" with pid %d", path, arguments or "",
                 self.pid)
        return True

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        process_handle = self.open_process()

        ret = KERNEL32.TerminateProcess(process_handle, 1)
        KERNEL32.CloseHandle(process_handle)

        if ret:
            log.info("Successfully terminated process with pid %d.", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d.", self.pid)
            return False

    def inject(self, dll=None, apc=False):
        """Inject our monitor into the specified process.
        @param dll: Cuckoo DLL path.
        @param apc: Use APC injection.
        """
        if not self.pid:
            log.warning("No valid pid specified, injection aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %s is not alive, "
                        "injection aborted", self.pid)
            return False

        if not dll:
            dll = "monitor-x86.dll"

        dll = randomize_dll(os.path.join("bin", dll))

        if not dll or not os.path.exists(dll):
            log.warning("No valid DLL specified to be injected in process "
                        "with pid %d, injection aborted.", self.pid)
            return False

        config_path = self.drop_config()

        inject_exe = os.path.join("bin", "inject-x86.exe")
        args = [
            inject_exe, "--pid", "%s" % self.pid, "--dll", dll,
            "--config", config_path,
        ]

        if apc:
            args += ["--apc", "--tid", "%s" % self.tid]
        else:
            args += ["--crt"]

        subprocess.check_output(args)

    def drop_config(self):
        """Helper function to drop the configuration for a new process."""
        fd, config_path = tempfile.mkstemp()
        os.close(fd)

        with open(config_path, "w") as config:
            cfg = Config("analysis.conf")
            cfgoptions = cfg.get_options()

            # The first time we come up with a random startup-time.
            if Process.first_process:
                # This adds 1 up to 30 times of 20 minutes to the startup
                # time of the process, therefore bypassing anti-vm checks
                # which check whether the VM has only been up for <10 minutes.
                Process.startup_time = random.randint(1, 30) * 20 * 60 * 1000

            hashes_path = os.path.join(os.getcwd(), "hashes.bin")

            config.write("host-ip={0}\n".format(cfg.ip))
            config.write("host-port={0}\n".format(cfg.port))
            config.write("pipe={0}\n".format(PIPE))
            config.write("results={0}\n".format(PATHS["root"]))
            config.write("analyzer={0}\n".format(os.getcwd()))
            config.write("first-process={0}\n".format("1" if Process.first_process else "0"))
            config.write("startup-time={0}\n".format(Process.startup_time))
            config.write("shutdown-mutex={0}\n".format(SHUTDOWN_MUTEX))
            config.write("force-sleepskip={0}\n".format(cfgoptions.get("force-sleepskip", "0")))
            config.write("hashes-path={0}\n".format(hashes_path))

            Process.first_process = False

        return config_path

    def dump_memory(self):
        """Dump process memory.
        @return: operation status.
        """
        if not self.pid:
            log.warning("No valid pid specified, memory dump aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %d is not alive, memory "
                        "dump aborted", self.pid)
            return False

        self.get_system_info()

        page_size = self.system_info.dwPageSize
        min_addr = self.system_info.lpMinimumApplicationAddress
        max_addr = self.system_info.lpMaximumApplicationAddress
        mem = min_addr

        root = os.path.join(PATHS["memory"], str(int(time())))

        if not os.path.exists(root):
            os.makedirs(root)

        # Now upload to host from the StringIO.
        nf = NetlogFile(os.path.join("memory", "%s.dmp" % str(self.pid)))

        process_handle = self.open_process()

        while mem < max_addr:
            mbi = MEMORY_BASIC_INFORMATION()
            count = c_ulong(0)

            if KERNEL32.VirtualQueryEx(process_handle,
                                       mem,
                                       byref(mbi),
                                       sizeof(mbi)) < sizeof(mbi):
                mem += page_size
                continue

            if mbi.State & MEM_COMMIT and \
                    mbi.Type & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE):
                buf = create_string_buffer(mbi.RegionSize)
                if KERNEL32.ReadProcessMemory(process_handle,
                                              mem,
                                              buf,
                                              mbi.RegionSize,
                                              byref(count)):
                    nf.sock.sendall(buf.raw)
                mem += mbi.RegionSize
            else:
                mem += page_size

        KERNEL32.CloseHandle(process_handle)
        nf.close()

        log.info("Memory dump of process with pid %d completed", self.pid)
        return True
