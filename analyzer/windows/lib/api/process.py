# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import random
import platform
from time import time
from ctypes import byref, c_ulong, create_string_buffer, c_int, sizeof, c_void_p, c_char_p, POINTER
from shutil import copy

from lib.common.constants import PIPE, PATHS, SHUTDOWN_MUTEX
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS, TH32CS_SNAPPROCESS
from lib.common.defines import STARTUPINFO, PROCESS_INFORMATION, PROCESSENTRY32
from lib.common.defines import CREATE_NEW_CONSOLE, CREATE_SUSPENDED
from lib.common.defines import MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE
from lib.common.defines import MEMORY_BASIC_INFORMATION
from lib.common.defines import WAIT_TIMEOUT
from lib.common.defines import MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
from lib.common.errors import get_error_string
from lib.common.rand import random_string
from lib.common.results import NetlogFile
from lib.core.config import Config

IOCTL_PID = 0x222008
IOCTL_CUCKOO_PATH = 0x22200C
PATH_KERNEL_DRIVER = "\\\\.\\DriverSSDT"

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 128

log = logging.getLogger(__name__)

def is_os_64bit():
    return platform.machine().endswith('64')

def randomize_dll(dll_path):
    """Randomize DLL name.
    @return: new DLL path.
    """
    new_dll_name = random_string(6)
    new_dll_path = os.path.join(os.getcwd(), "dll", "{0}.dll".format(new_dll_name))

    try:
        copy(dll_path, new_dll_path)
        return new_dll_path
    except:
        return dll_path

class Process:
    """Windows process."""
    first_process = True

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
        self.event_handle = None

    def __del__(self):
        """Close open handles."""
        if self.h_process and self.h_process != KERNEL32.GetCurrentProcess():
            KERNEL32.CloseHandle(self.h_process)
        if self.h_thread:
            KERNEL32.CloseHandle(self.h_thread)

    def get_system_info(self):
        """Get system information."""
        self.system_info = SYSTEM_INFO()
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open(self):
        """Open a process and/or thread.
        @return: operation status.
        """
        ret = bool(self.pid or self.thread_id)
        if self.pid and not self.h_process:
            if self.pid == os.getpid():
                self.h_process = KERNEL32.GetCurrentProcess()
            else:
                self.h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                                      False,
                                                      self.pid)
            ret = True

        if self.thread_id and not self.h_thread:
            self.h_thread = KERNEL32.OpenThread(THREAD_ALL_ACCESS,
                                                False,
                                                self.thread_id)
            ret = True
        return ret

    def close(self):
        """Close any open handles.
        @return: operation status.
        """
        ret = bool(self.h_process or self.h_thread)
        NT_SUCCESS = lambda val: val >= 0

        if self.h_process:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_process))

        if self.h_thread:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_thread))

        return ret

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        if not self.h_process:
            self.open()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(self.h_process, byref(exit_code))

        return exit_code.value

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        pbi = create_string_buffer(200)
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process,
                                              27,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        if NT_SUCCESS(ret) and size.value > 8:
            try:
                fbuf = pbi.raw[8:]
                fbuf = fbuf[:fbuf.find('\0\0')+1]
                return fbuf.decode('utf16', errors="ignore")
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
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        pbi = (c_int * 6)()
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process,
                                              0,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        if NT_SUCCESS(ret) and size.value == sizeof(pbi):
            return pbi[5]

        return None

    def execute(self, path, args=None, suspended=False, kernel_analysis=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param suspended: is suspended.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error("Unable to access file at path \"%s\", "
                      "execution aborted", path)
            return False

        startup_info = STARTUPINFO()
        startup_info.cb = sizeof(startup_info)
        # STARTF_USESHOWWINDOW
        startup_info.dwFlags = 1
        # SW_SHOWNORMAL
        startup_info.wShowWindow = 1
        process_info = PROCESS_INFORMATION()

        arguments = "\"" + path + "\" "
        if args:
            arguments += args

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
                                          os.getenv("TEMP"),
                                          byref(startup_info),
                                          byref(process_info))

        if created:
            self.pid = process_info.dwProcessId
            self.h_process = process_info.hProcess
            self.thread_id = process_info.dwThreadId
            self.h_thread = process_info.hThread
            log.info("Successfully executed process from path \"%s\" with "
                     "arguments \"%s\" with pid %d", path, args or "", self.pid)
            
        
            if kernel_analysis == True:
                log.info("Starting kernel analysis")
                log.info("Installing driver")
                if is_os_64bit():
                    sys_file = os.path.join(os.getcwd(), "dll", "zer0m0n_x64.sys")
                else:
                    sys_file = os.path.join(os.getcwd(), "dll", "zer0m0n.sys")
                exe_file = os.path.join(os.getcwd(), "dll", "logs_dispatcher.exe")
                if not sys_file or not exe_file or not os.path.exists(sys_file) or not os.path.exists(exe_file):
                    log.warning("No valid zer0m0n files to be used for process with pid %d, injection aborted", self.pid)
                    return False
            
                exe_name = random_string(6)
                service_name = random_string(6)
                driver_name = random_string(6)
    
                inf_data = '[Version]\r\nSignature = "$Windows NT$"\r\nClass = "ActivityMonitor"\r\nClassGuid = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}\r\nProvider= %Prov%\r\nDriverVer = 22/01/2014,1.0.0.0\r\nCatalogFile = %DriverName%.cat\r\n[DestinationDirs]\r\nDefaultDestDir = 12\r\nMiniFilter.DriverFiles = 12\r\n[DefaultInstall]\r\nOptionDesc = %ServiceDescription%\r\nCopyFiles = MiniFilter.DriverFiles\r\n[DefaultInstall.Services]\r\nAddService = %ServiceName%,,MiniFilter.Service\r\n[DefaultUninstall]\r\nDelFiles = MiniFilter.DriverFiles\r\n[DefaultUninstall.Services]\r\nDelService = %ServiceName%,0x200\r\n[MiniFilter.Service]\r\nDisplayName= %ServiceName%\r\nDescription= %ServiceDescription%\r\nServiceBinary= %12%\\%DriverName%.sys\r\nDependencies = "FltMgr"\r\nServiceType = 2\r\nStartType = 3\r\nErrorControl = 1\r\nLoadOrderGroup = "FSFilter Activity Monitor"\r\nAddReg = MiniFilter.AddRegistry\r\n[MiniFilter.AddRegistry]\r\nHKR,,"DebugFlags",0x00010001 ,0x0\r\nHKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%\r\nHKR,"Instances\\"%Instance1.Name%,"Altitude",0x00000000,%Instance1.Altitude%\r\nHKR,"Instances\\"%Instance1.Name%,"Flags",0x00010001,%Instance1.Flags%\r\n[MiniFilter.DriverFiles]\r\n%DriverName%.sys\r\n[SourceDisksFiles]\r\n'+driver_name+'.sys = 1,,\r\n[SourceDisksNames]\r\n1 = %DiskId1%,,,\r\n[Strings]\r\n'+'Prov = "'+random_string(8)+'"\r\nServiceDescription = "'+random_string(12)+'"\r\nServiceName = "'+service_name+'"\r\nDriverName = "'+driver_name+'"\r\nDiskId1 = "'+service_name+' Device Installation Disk"\r\nDefaultInstance = "'+service_name+' Instance"\r\nInstance1.Name = "'+service_name+' Instance"\r\nInstance1.Altitude = "370050"\r\nInstance1.Flags = 0x0'

                new_inf = os.path.join(os.getcwd(), "dll", "{0}.inf".format(service_name))
                new_sys = os.path.join(os.getcwd(), "dll", "{0}.sys".format(driver_name))
                copy(sys_file, new_sys)
                new_exe = os.path.join(os.getcwd(), "dll", "{0}.exe".format(exe_name))
                copy(exe_file, new_exe)
                log.info("[-] Driver name : "+new_sys)
                log.info("[-] Inf name : "+new_inf)
                log.info("[-] Application name : "+new_exe)
                log.info("[-] Service : "+service_name)

                fh = open(new_inf,"w")
                fh.write(inf_data)
                fh.close()

                if is_os_64bit():
                    wow64 = c_ulong(0)
                    KERNEL32.Wow64DisableWow64FsRedirection(byref(wow64))

                os.system('cmd /c "rundll32 setupapi.dll, InstallHinfSection DefaultInstall 132 '+new_inf+'"')
                os.system("net start "+service_name)

                si = STARTUPINFO()
                si.cb = sizeof(startup_info)
                pi = PROCESS_INFORMATION()
                cr = CREATE_NEW_CONSOLE
                ldp = KERNEL32.CreateProcessA(new_exe,
                                              None,
                                              None,
                                              None,
                                              None,
                                              cr,
                                              None,
                                              os.getenv("TEMP"),
                                              byref(si),
                                              byref(pi))

                if not ldp:
                    log.error("Failed starting "+exe_name+".exe.")
                    return False

                config_path = os.path.join(os.getenv("TEMP"), "%s.ini" % self.pid)
                with open(config_path, "w") as config:
                    cfg = Config("analysis.conf")
            
                    config.write("host-ip={0}\n".format(cfg.ip))
                    config.write("host-port={0}\n".format(cfg.port))
                    config.write("pipe={0}\n".format(PIPE))

                log.info("Sending startup information")
                hFile = KERNEL32.CreateFileA(PATH_KERNEL_DRIVER, GENERIC_READ|GENERIC_WRITE,
                                             0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    
                if hFile:
                    p = Process(pid=os.getpid())
                    ppid = p.get_parent_pid()
                    pid_vboxservice = 0
                    pid_vboxtray = 0

                    # get pid of VBoxService.exe and VBoxTray.exe
                    proc_info = PROCESSENTRY32()
                    proc_info.dwSize = sizeof(PROCESSENTRY32)
                
                    snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                    flag = KERNEL32.Process32First(snapshot, byref(proc_info))
                    while flag:
                        if proc_info.sz_exeFile == "VBoxService.exe":
                            log.info("VBoxService.exe found !")
                            pid_vboxservice = proc_info.th32ProcessID
                            flag = 0
                        elif proc_info.sz_exeFile == "VBoxTray.exe":
                            pid_vboxtray = proc_info.th32ProcessID
                            log.info("VBoxTray.exe found !")
                            flag = 0
                        flag = KERNEL32.Process32Next(snapshot, byref(proc_info))
                    msg = str(self.pid)+"_"+str(ppid)+"_"+str(os.getpid())+"_"+str(pi.dwProcessId)+"_"+str(pid_vboxservice)+"_"+str(pid_vboxtray)+'\0'
                    buf = create_string_buffer(128)
                    length = c_int()
                    KERNEL32.DeviceIoControl.argtypes = [c_int, c_int, c_char_p, c_int, c_void_p, c_int, POINTER(c_int), c_void_p]
                    KERNEL32.DeviceIoControl(hFile, IOCTL_PID, msg, len(msg), byref(buf), 128, byref(length), None)
                    msg = os.getcwd()+'\0'             
                    KERNEL32.DeviceIoControl(hFile, IOCTL_CUCKOO_PATH, unicode(msg), len(msg), byref(buf), 128, byref(length), None)
                else:
                    log.warning("Failed to access kernel driver")         
            
            return True
        else:
            log.error("Failed to execute process from path \"%s\" with "
                      "arguments \"%s\" (Error: %s)", path, args,
                      get_error_string(KERNEL32.GetLastError()))
            return False

    def resume(self):
        """Resume a suspended thread.
        @return: operation status.
        """
        if not self.suspended:
            log.warning("The process with pid %d was not suspended at creation"
                        % self.pid)
            return False

        if not self.h_thread:
            return False

        KERNEL32.Sleep(2000)

        if KERNEL32.ResumeThread(self.h_thread) != -1:
            log.info("Successfully resumed process with pid %d", self.pid)
            return True
        else:
            log.error("Failed to resume process with pid %d", self.pid)
            return False

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        if self.h_process == 0:
            self.open()

        if KERNEL32.TerminateProcess(self.h_process, 1):
            log.info("Successfully terminated process with pid %d.", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d.", self.pid)
            return False

    def inject(self, dll=None, apc=False):
        """Cuckoo DLL injection.
        @param dll: Cuckoo DLL path.
        @param apc: APC use.
        """
        if not self.pid:
            log.warning("No valid pid specified, injection aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %s is not alive, "
                        "injection aborted", self.pid)
            return False

        if not dll:
            dll = "cuckoomon.dll"

        dll = randomize_dll(os.path.join("dll", dll))

        if not dll or not os.path.exists(dll):
            log.warning("No valid DLL specified to be injected in process "
                        "with pid %d, injection aborted.", self.pid)
            return False

        arg = KERNEL32.VirtualAllocEx(self.h_process,
                                      None,
                                      len(dll) + 1,
                                      MEM_RESERVE | MEM_COMMIT,
                                      PAGE_READWRITE)

        if not arg:
            log.error("VirtualAllocEx failed when injecting process with "
                      "pid %d, injection aborted (Error: %s)",
                      self.pid, get_error_string(KERNEL32.GetLastError()))
            return False

        bytes_written = c_int(0)
        if not KERNEL32.WriteProcessMemory(self.h_process,
                                           arg,
                                           dll + "\x00",
                                           len(dll) + 1,
                                           byref(bytes_written)):
            log.error("WriteProcessMemory failed when injecting process with "
                      "pid %d, injection aborted (Error: %s)",
                      self.pid, get_error_string(KERNEL32.GetLastError()))
            return False

        kernel32_handle = KERNEL32.GetModuleHandleA("kernel32.dll")
        load_library = KERNEL32.GetProcAddress(kernel32_handle, "LoadLibraryA")

        config_path = os.path.join(os.getenv("TEMP"), "%s.ini" % self.pid)
        with open(config_path, "w") as config:
            cfg = Config("analysis.conf")
            cfgoptions = cfg.get_options()

            # The first time we come up with a random startup-time.
            if Process.first_process:
                # This adds 1 up to 30 times of 20 minutes to the startup
                # time of the process, therefore bypassing anti-vm checks
                # which check whether the VM has only been up for <10 minutes.
                Process.startup_time = random.randint(1, 30) * 20 * 60 * 1000

            config.write("host-ip={0}\n".format(cfg.ip))
            config.write("host-port={0}\n".format(cfg.port))
            config.write("pipe={0}\n".format(PIPE))
            config.write("results={0}\n".format(PATHS["root"]))
            config.write("analyzer={0}\n".format(os.getcwd()))
            config.write("first-process={0}\n".format("1" if Process.first_process else "0"))
            config.write("startup-time={0}\n".format(Process.startup_time))
            config.write("shutdown-mutex={0}\n".format(SHUTDOWN_MUTEX))
            config.write("force-sleepskip={0}\n".format(cfgoptions.get("force-sleepskip", "0")))

            Process.first_process = False

        event_name = "CuckooEvent%d" % self.pid
        self.event_handle = KERNEL32.CreateEventA(None, False, False, event_name)
        if not self.event_handle:
            log.warning("Unable to create notify event..")
            return False

        if apc or self.suspended:
            log.debug("Using QueueUserAPC injection.")
            if not self.h_thread:
                log.info("No valid thread handle specified for injecting "
                         "process with pid %d, injection aborted.", self.pid)
                self.event_handle = None
                return False

            if not KERNEL32.QueueUserAPC(load_library, self.h_thread, arg):
                log.error("QueueUserAPC failed when injecting process with "
                          "pid %d (Error: %s)",
                          self.pid, get_error_string(KERNEL32.GetLastError()))
                self.event_handle = None
                return False
        else:
            log.debug("Using CreateRemoteThread injection.")
            new_thread_id = c_ulong(0)
            thread_handle = KERNEL32.CreateRemoteThread(self.h_process,
                                                        None,
                                                        0,
                                                        load_library,
                                                        arg,
                                                        0,
                                                        byref(new_thread_id))
            if not thread_handle:
                log.error("CreateRemoteThread failed when injecting process "
                          "with pid %d (Error: %s)",
                          self.pid, get_error_string(KERNEL32.GetLastError()))
                KERNEL32.CloseHandle(self.event_handle)
                self.event_handle = None
                return False
            else:
                KERNEL32.CloseHandle(thread_handle)

        log.info("Successfully injected process with pid %d." % self.pid)

        return True

    def wait(self):
        ret = True

        if self.event_handle:
            retval = KERNEL32.WaitForSingleObject(self.event_handle, 10000)
            if retval == WAIT_TIMEOUT:
                log.error("Timeout waiting for cuckoomon to initialize in pid %d", self.pid)
                ret = False
            else:
                log.info("Successfully injected process with pid %d", self.pid)

            KERNEL32.CloseHandle(self.event_handle)
            self.event_handle = None

        return ret

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

        while mem < max_addr:
            mbi = MEMORY_BASIC_INFORMATION()
            count = c_ulong(0)

            if KERNEL32.VirtualQueryEx(self.h_process,
                                       mem,
                                       byref(mbi),
                                       sizeof(mbi)) < sizeof(mbi):
                mem += page_size
                continue

            if mbi.State & MEM_COMMIT and \
                    mbi.Type & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE):
                buf = create_string_buffer(mbi.RegionSize)
                if KERNEL32.ReadProcessMemory(self.h_process,
                                              mem,
                                              buf,
                                              mbi.RegionSize,
                                              byref(count)):
                    nf.sock.sendall(buf.raw)
                mem += mbi.RegionSize
            else:
                mem += page_size

        nf.close()

        log.info("Memory dump of process with pid %d completed", self.pid)

        return True
