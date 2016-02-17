# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import random
import subprocess
import tempfile
from ctypes import byref, c_ulong, create_string_buffer, c_int, sizeof
from ctypes import c_uint, c_wchar_p, create_unicode_buffer

from lib.common.constants import SHUTDOWN_MUTEX
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS
from lib.common.errors import get_error_string
from lib.common.exceptions import CuckooError
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

class Process(object):
    """Windows process."""
    first_process = True
    config = None

    # Keeps track of the dump memory index for a particular process as in
    # theory, and will be useful later, we may want to dump one process
    # multiple times.
    dumpmem = {}

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

        is32bit = self.is32bit(path=path)

        if not dll:
            if is32bit:
                dll = "monitor-x86.dll"
            else:
                dll = "monitor-x64.dll"

        dllpath = os.path.abspath(os.path.join("bin", dll))

        if not os.path.exists(dllpath):
            log.warning("No valid DLL specified to be injected, "
                        "injection aborted.")
            return False

        if is32bit:
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        argv = [inject_exe, "--app", self.shortpath(path)]

        if args:
            argv += ["--args", self._encode_args(args)]

        if free:
            argv += ["--free"]
        else:
            argv += ["--apc", "--dll", dllpath,
                     "--config", self.drop_config(mode=mode)]

        if curdir:
            argv += ["--curdir", self.shortpath(curdir)]

        if source:
            if isinstance(source, (int, long)) or source.isdigit():
                argv += ["--from", "%s" % source]
            else:
                argv += ["--from-process", source]

        if maximize:
            argv += ["--maximize"]

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
                        "injection aborted.")
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
            log.error("Failed to inject %s-bit process with pid %s and "
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
            "analyzer": os.getcwd(),
            "first-process": "1" if Process.first_process else "0",
            "startup-time": Process.startup_time,
            "shutdown-mutex": SHUTDOWN_MUTEX,
            "force-sleepskip": self.config.options.get("force-sleepskip", "0"),
            "track": "1" if track else "0",
            "mode": mode or "",
            "disguise": self.config.options.get("disguise", "0"),
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

        if self.is32bit(pid=self.pid):
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        # Take the memory dump.
        dump_path = tempfile.mktemp()

        try:
            args = [
                inject_exe,
                "--pid", "%s" % self.pid,
                "--dump", dump_path,
            ]
            subprocess.check_call(args)
        except subprocess.CalledProcessError:
            log.error("Failed to dump memory of %d-bit process with pid %d.",
                      32 if self.is32bit(pid=self.pid) else 64, self.pid)
            return

        # Calculate the next index and send the process memory dump over to
        # the host. Keep in mind that one process may have multiple process
        # memory dumps in the future.
        idx = self.dumpmem[self.pid] = self.dumpmem.get(self.pid, 0) + 1
        file_name = os.path.join("memory", "%s-%s.dmp" % (self.pid, idx))
        upload_to_host(dump_path, file_name)
        os.unlink(dump_path)

        log.info("Memory dump of process with pid %d completed", self.pid)
        return True
