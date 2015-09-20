# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import random
import subprocess
import tempfile
import time
from ctypes import byref, c_ulong, create_string_buffer, c_int, sizeof
from ctypes import c_uint, c_wchar_p, create_unicode_buffer

from lib.common.constants import PATHS, SHUTDOWN_MUTEX
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS
from lib.common.defines import MEM_COMMIT, MEMORY_BASIC_INFORMATION
from lib.common.defines import MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
from lib.common.errors import get_error_string
from lib.common.exceptions import CuckooError
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)

class Process(object):
    """Windows process."""
    first_process = True
    config = None

    def __init__(self, pid=None, tid=None, process_name=None):
        """
        @param pid: process identifier.
        @param tid: thread identifier.
        @param process_name: process name.
        """
        self.pid = pid
        self.tid = tid
        self.process_name = process_name

    @staticmethod
    def set_config(config):
        """Sets the analyzer configuration once."""
        Process.config = config

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

    def shortpath(self, path):
        """Returns the shortpath for a file.

        As Python 2.7 does not support passing along unicode strings in
        subprocess.Popen() and alike this will have to do. See also:
        http://stackoverflow.com/questions/2595448/unicode-filename-to-python-subprocess-call
        """
        KERNEL32.GetShortPathNameW.restype = c_uint
        KERNEL32.GetShortPathNameW.argtypes = c_wchar_p, c_wchar_p, c_uint

        buf = create_unicode_buffer(0x8000)
        KERNEL32.GetShortPathNameW(path, buf, len(buf))
        return buf.value

    def _encode_args(self, args):
        """Convert a list of arguments to a string that can be passed along
        on the command-line.
        @param args: list of arguments
        @return: the command-line equivalent
        """
        ret = []
        for line in args:
            if " " in line or '"' in line:
                ret.append("\"%s\"" % line.replace('"', '\\"'))
            else:
                ret.append(line)
        return " ".join(ret)

    def is32bit(self, pid=None, process_name=None, path=None):
        """Is a PE file 32-bit or does a process identifier belong to a
        32-bit process.
        @param pid: process identifier.
        @param process_name: process name.
        @param path: path to a PE file.
        @return: boolean or exception.
        """
        count = (pid is None) + (process_name is None) + (path is None)
        if count != 2:
            raise CuckooError("Invalid usage of is32bit, only one identifier "
                              "should be specified")

        is32bit_exe = os.path.join("bin", "is32bit.exe")

        if pid:
            args = [is32bit_exe, "-p", "%s" % pid]
        elif process_name:
            args = [is32bit_exe, "-n", process_name]
        # If we're running a 32-bit Python in a 64-bit Windows system and the
        # path points to System32, then we hardcode it as being a 64-bit
        # binary. (To be fair, a 64-bit Python on 64-bit Windows would also
        # make the System32 binary 64-bit).
        elif os.path.isdir("C:\\Windows\\Sysnative") and \
                path.lower().startswith("c:\\windows\\system32"):
            return False
        else:
            args = [is32bit_exe, "-f", self.shortpath(path)]

        try:
            bitsize = int(subprocess.check_output(args))
        except subprocess.CalledProcessError as e:
            raise CuckooError("Error returned by is32bit: %s" % e)

        return bitsize == 32

    def execute(self, path, args=None, dll=None, free=False, curdir=None,
                source=None, mode=None, maximize=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param dll: dll path.
        @param free: do not inject our monitor.
        @param curdir: current working directory.
        @param source: process identifier or process name which will
                       become the parent process for the new process.
        @param mode: monitor mode - which functions to instrument.
        @param maximize: whether the GUI should be maximized.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error("Unable to access file at path \"%s\", "
                      "execution aborted", path)
            return False

        if source:
            source_is32bit = self.is32bit(process_name=source)
        else:
            source_is32bit = self.is32bit(pid=os.getpid())

        sample_is32bit = self.is32bit(path=path)

        if not dll:
            if sample_is32bit:
                dll = "monitor-x86.dll"
            else:
                dll = "monitor-x64.dll"

        dllpath = os.path.abspath(os.path.join("bin", dll))
        if not os.path.exists(dllpath):
            log.warning("No valid DLL specified to be injected, "
                        "injection aborted.")
            return False

        if source_is32bit:
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        # The --free is required because otherwise we have to provide a DLL
        # to inject even though we won't be injecting anything at this point.
        argv = [
            inject_exe, "--app", self.shortpath(path),
            "--only-start", "--free",
        ]

        if args:
            argv += ["--args", self._encode_args(args)]

        if curdir:
            argv += ["--curdir", self.shortpath(curdir)]

        if maximize:
            argv += ["--maximize"]

        if source:
            argv += ["--from-process", source]
        else:
            argv += ["--from", "%s" % os.getpid()]

        try:
            pid, tid = subprocess.check_output(argv).strip().split()
        except Exception:
            log.error("Failed to execute process from path %r with "
                      "arguments %r (Error: %s)", path, argv,
                      get_error_string(KERNEL32.GetLastError()))
            return False

        if free:
            return True

        if sample_is32bit:
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        argv = [
            inject_exe, "--apc", "--dll", dllpath,
            "--pid", pid, "--tid", tid, "--resume-thread",
            "--config", self.drop_config(mode=mode),
        ]

        try:
            self.pid = int(subprocess.check_output(argv))
        except Exception:
            log.error("Failed to execute process from path %r with "
                      "arguments %r (Error: %s)", path, argv,
                      get_error_string(KERNEL32.GetLastError()))
            return False

        log.info("Successfully executed process from path %r with "
                 "arguments %r and pid %d", path, args or "", self.pid)
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

    def inject(self, dll=None, apc=False, track=True, mode=None):
        """Inject our monitor into the specified process.
        @param dll: Cuckoo DLL path.
        @param apc: Use APC injection.
        @param track: Track this process in the analyzer.
        @param mode: Monitor mode - which functions to instrument.
        """
        if not self.pid and not self.process_name:
            log.warning("No valid pid or process name specified, "
                        "injection aborted")
            return False

        # Only check whether the process is still alive when it's identified
        # by a process identifier. Not when it's identified by a process name.
        if not self.process_name and not self.is_alive():
            log.warning("The process with pid %s is not alive, "
                        "injection aborted", self.pid)
            return False

        if self.process_name:
            is32bit = self.is32bit(process_name=self.process_name)
        elif self.pid:
            is32bit = self.is32bit(pid=self.pid)

        if not dll:
            if is32bit:
                dll = "monitor-x86.dll"
            else:
                dll = "monitor-x64.dll"

        dllpath = os.path.abspath(os.path.join("bin", dll))

        if not os.path.exists(dllpath):
            log.warning("No valid DLL specified to be injected in process "
                        "with pid %s / process name %s, injection aborted.",
                        self.pid, self.process_name)
            return False

        if is32bit:
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        args = [
            inject_exe, "--dll", dllpath,
            "--config", self.drop_config(track=track, mode=mode),
        ]

        if self.pid:
            args += ["--pid", "%s" % self.pid]
        elif self.process_name:
            args += ["--process-name", self.process_name]

        if apc:
            args += ["--apc", "--tid", "%s" % self.tid]
        else:
            args += ["--crt"]

        try:
            subprocess.check_call(args)
        except Exception:
            log.error("Failed to inject %s process with pid %s and "
                      "process name %s", 32 if is32bit else 64, self.pid,
                      self.process_name)
            return False

        log.info("Successfully injected process with pid %s", self.pid)
        return True

    def drop_config(self, track=True, mode=None):
        """Helper function to drop the configuration for a new process."""
        fd, config_path = tempfile.mkstemp()

        # The first time we come up with a random startup-time.
        if Process.first_process:
            # This adds 1 up to 30 times of 20 minutes to the startup
            # time of the process, therefore bypassing anti-vm checks
            # which check whether the VM has only been up for <10 minutes.
            Process.startup_time = random.randint(1, 30) * 20 * 60 * 1000

        lines = {
            "host-ip": self.config.ip,
            "host-port": self.config.port,
            "pipe": self.config.pipe,
            "logpipe": self.config.logpipe,
            "results": PATHS["root"],
            "analyzer": os.getcwd(),
            "first-process": "1" if Process.first_process else "0",
            "startup-time": Process.startup_time,
            "shutdown-mutex": SHUTDOWN_MUTEX,
            "force-sleepskip": self.config.options.get("force-sleepskip", "0"),
            "hashes-path": os.path.join(os.getcwd(), "hashes.bin"),
            "track": "1" if track else "0",
            "mode": mode or "",
        }

        for key, value in lines.items():
            os.write(fd, "%s=%s\n" % (key, value))

        os.close(fd)
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

        root = os.path.join(PATHS["memory"], str(int(time.time())))

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
