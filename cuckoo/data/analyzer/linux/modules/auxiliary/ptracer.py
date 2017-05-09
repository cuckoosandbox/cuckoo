# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

'''
deps
pathtools
watchdog
python-ptrace == 0.9.2
'''

# http://python-ptrace.readthedocs.io/
# https://gist.github.com/yoggy/3011428

import os
import sys
import json
import time
import platform
import logging
import collections
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger import (ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from ptrace.func_call import FunctionCallOptions
from ptrace.ctypes_tools import formatAddress
from ptrace.error import PtraceError, PTRACE_ERRORS
from ptrace.syscall import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
from errno import EPERM
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread

"""
from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
"""
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

# Quick and dirty way to categorize some syscalls
SOCKET_SYSCALL_FILESYSTEM_NAMES = set(("read", "write", "open", "close", "stat", "fstat",
                                   "lstat", "poll", "lseek", "access","mkdir", "rename",
                                   "rmdir", "creat", "link", "unlink", "symlink", "readlink",
                                   "chmod", "fchmod", "chown", "fchown", "lchown","umask",
                                   ))
SOCKET_SYSCALL_PROCESS_NAMES = set(("mmap", "mprotect", "brk", "clone", "fork", "vfork",
                                "execve", "exit", "kill","chdir","fchdir","sysinfo","ptrace"
                                ))

def get_key(pos):
    return pos*2

def get_value(pos):
    return pos*2+1

#https://github.com/0x71/cuckoo/blob/1faed4a62dea4597111be7ce60f45bb9262188cb/analyzer/linux/lib/core/netlog.py
class ResultLogger():
    def resolve_category(self, name, args):
        if name in SOCKET_SYSCALL_NAMES:
            return "network"
        elif name in SOCKET_SYSCALL_FILESYSTEM_NAMES:
            return "filesystem"
        elif name in SOCKET_SYSCALL_PROCESS_NAMES:
            return "process"
        else:
            for arg in args:
                if isinstance(arg, str):
                    if "filename" in arg:
                        return "filesystem"
        return "unkown"

class STRACER():#Auxiliary):
    """system-wide syscall trace with ptrace."""
    priority = -10 # low prio to wrap tightly around the analysis

    def start(self):
        # Start file system tracer thread
        self.fstrace = FilesystemTracer()
        self.fstrace.start()

        # Start system call tracer thread
        self.proctrace = SyscallTracer()
        self.proctrace.start()
        #pass
    def stop(self):

        self.fstrace.stop()
        self.proctrace.stop()
        #pass


class MyHandler(FileSystemEventHandler):
    """ Logs all the events captured. """
    def on_moved(self, event):
        super(MyHandler, self).on_moved(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Moved %s: from %s to %s", what, event.src_path,
                     event.dest_path)

    def on_created(self, event):
        super(MyHandler, self).on_created(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Created %s: %s", what, event.src_path)

    def on_deleted(self, event):
        super(MyHandler, self).on_deleted(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Deleted %s: %s", what, event.src_path)

    def on_modified(self, event):
        super(MyHandler, self).on_modified(event)

        what = 'directory' if event.is_directory else 'file'
        log.info("Modified %s: %s", what, event.src_path)


class FilesystemTracer(Thread):
    """ FilesystemTracer.

        File system tracer observes specific directories for several activities
        (create, delete, modify and move).
    """

    def __init__(self):
        """ Init thread, event handler and observer classes.
            init some default paths to observe.
        """
        Thread.__init__(self)
        log.debug('FilesystemTracer started.')
        self.directory_paths = [['/etc/',True],
                           ['/proc/sys', True],
                           ['/tmp', True],
                           ['/var/tmp', True]]
        self.event_handler = MyHandler()
        self.observer = Observer()

        self.prepare()

    def prepare(self):
        for path in self.directory_paths:
            log.debug('Monitoring %s, recursive=%s', path[0], path[1])
            self.observer.schedule(self.event_handler, str(path[0]), recursive=path[1])

    def start(self):
        """ Run Watchdog observer """
        self.observer.start()

    def stop(self):
        """ Stop observer. """
        self.observer.stop()

    def join(self):
        """ Wait for threads """
        self.observer.join()

    def add_directory(self,path,recursive=True):
        """ Add a directory to observer scheduler """
        log.debug('Monitoring %s, recursive=%s',path,recursive)
        #self.directory_paths.append([path,recursive])
        self.observer.schedule(self.event_handler, path, recursive)


class SyscallTracer(Thread):
    ''' Trace and control processes using (python)-ptrace '''
    def __init__(self, program):
        log.debug("SyscallTracer started.")
        Thread.__init__(self)
        self.program = program
        self.no_stdout = False
        self.do_run = True
        self.remote_log = collections.OrderedDict()

    def run_debugger(self):
        ''' init and run debugger '''
        # Set Options to trace fork and exec calls
        self.debugger.traceFork()
        self.debugger.traceExec()

        # Create traced process
        process = self.create_process()
        if not process:
            return

        self.remote_log[process.pid] = collections.OrderedDict()
        #self.remote_log[process.pid].log_init(time.time())
        #self.remote_log.setdefault(process.pid, dict()) =
        log.info(
            {process.pid: {
                "TimeStamp": long(round(time.time() * 1000)),
                "ProcessIdentifier": process.pid,
                "ParentProcessIdentifier": os.getpid(),
                "ModulePath":  ""
            }
        })
        #log.debug("Logging for %d started.", process.pid)

        # Set syscall options (print options)
        self.syscall_options = FunctionCallOptions(
            write_types=False,
            write_argname=True,
            string_max_length=8192,
            replace_socketcall=True,
            write_address=False,
            max_array_count=100,
        )

        # Start process tracing
        self.trace_syscall(process)

    def trace_syscall(self, process):
        ''' Main process trace method '''
        # Break at first syscall
        # (https://github.com/qikon/python-ptrace/blob/master/ptrace/debugger/process.py)
        process.syscall()

        while self.do_run:
            # No process?
            if not self.debugger:
                break;

            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                state = event.process.syscall_state
                if (state.next_event == "exit") and state.syscall:
                    #log.debug("[%d] exit() : exit process", event.process.pid)
                    self.debugger.deleteProcess(pid=event.process.pid)
                continue
            except ProcessSignal, event:
                #log.debug("*** SIGNAL pid=%s ***", event.process.pid)
                #event.display()
                event.process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.new_process(event)
                continue
            except ProcessExecution, event:
                #log.debug("*** Process %s execution ***", event.process.pid)
                event.process.syscall()
                continue
            #log.info(1)
            #log.info(dir(process))
            # Process syscall enter or exit
            self.get_syscall_str(process)
            # Break at next syscall
            process.syscall()

    def new_process(self, event):
        ''' Event handler.
            Used to trace new child processes.
        '''
        #process = event.process
        #log.info(2)
        #log.info(dir(event.process))
        #log.info("\n\n*** New process %s ***" % event.process.pid)

        #self.remote_log[process.pid] = collections.OrderedDict()
        #self.remote_log[process.pid].log_init(time.time())

        self.remote_log.setdefault(event.process.pid, dict()).setdefault("start",
        {
            "TimeStamp": long(round(time.time() * 1000)),
            "ProcessIdentifier": event.process.pid,
            "ParentProcessIdentifier":  event.process.parent.pid,
            "ModulePath":  None
        })

        log.info(
            {process.pid: {
                "TimeStamp": long(round(time.time() * 1000)),
                "ProcessIdentifier": event.process.pid,
                "ParentProcessIdentifier": event.process.parent.pid,
                "ModulePath":  ""
            }
        })
        #log.info(self.remote_log[event.process.pid])
        event.process.syscall()
        event.process.parent.syscall()

    def create_process(self):
        ''' create a process and add it to debugger '''
        #pid = self.create_child(self.program)
        pid = int(self.program)

        try:
            # False if we attach to pid, True if to start process
            return self.debugger.addProcess(pid, False)
        except (ProcessExit, PtraceError) as e:
            if isinstance(e, PtraceError) and e.errno == EPERM:
                log.error("You are not allowed to trace process %s (permission denied or process already traced)", pid)
            else:
                log.error("Process can no be attached! %s", e)
        return None

    def create_child(self, program, env=None):
        ''' Fork a new child process '''
        pid = createChild(program, self.no_stdout, env)
        #log.debug("execve(%s, %s, [/* 40 vars */]) = %s", program[0], program, pid)
        return pid

    def hide_me(self, syscall, process):
        ''' Prevent tracer detection '''
        # Identify ptrace syscall

        if "ptrace" in syscall.name:
            arch = platform.machine()
            # change return value of ptrace syscall to 0
            # x86_64
            register = "rax"
            if arch == "i386":
                register = "eax"
            elif arch == "powerpc":
                register = "r3"
            elif arch.startswith("arm"):
                register = "r0"
            elif arch.startswith("sparc"):
                register = "rd"
            elif arch.startswith("mips"):
                register = "v0"
            process.setreg(register, 0)

    def start(self):
        ''' init and run debugger '''
        self.debugger = PtraceDebugger()
        try:
            self.run_debugger()
        except ProcessExit, event:
            self.processExited(event)
        except PtraceError as e:
            log.debug("ptrace() error: %s", e)
        except KeyboardInterrupt:
            self.do_run = False
            #log.debug("Interrupted.")
        except PTRACE_ERRORS as e:
            log.debug("Debugger error: %s", e)
        self.debugger.quit()
        self.do_run = False

        log.info(self.remote_log)
        dump_log = open("stracer.json", "wb")
        dump_log.write(json.dumps(self.remote_log))
        dump_log.close()

    def stop(self):
        """Stop syscall tracer."""
        self.do_run = False

    def log_resolve_index(self, name):
        for index, value in SYSCALL_NAMES.items():
            if value == name:
                return index
        return -1

    def is_running(self):
        """Check tracer status
        @return: run status.
        """
        return self.directory_pathsrun

    def get_syscall_str(self, process):
        ''' Print catched syscalls '''
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall and (syscall.result is not None):
            name = syscall.name
            text = syscall.format()
            # print syscall.name, syscall.restype, syscall.resvalue, self.remote_log[process.pid].log_resolve_index(syscall.name)
            arg_list = []
            for arg in syscall.arguments:
                arg_list.append(arg.name)
                arg_list.append(arg.getText())

            prefix = []
            prefix.append("[%s]" % process.pid)
            text = ''.join(prefix) + ' ' + text
            log.debug(text)
            self.hide_me(syscall, process)

            #index = self.remote_log[process.pid].log_resolve_index(syscall.name)
            #log.info(self.log_resolve_index(syscall.name))
            tmp = syscall.result_text.split()
            success = 0 if int(tmp[0],16) < 0 else 1
            #log.info(self.log_resolve_index(syscall.name))
            #log.info(dir(process.pid))
            self.remote_log.setdefault(process.pid, dict()).setdefault("start",
            {
                "TimeStamp": long(round(time.time() * 1000)),
                "ProcessIdentifier": process.pid,
                "ParentProcessIdentifier":  process.parent.pid if hasattr(process.parent, "pid") else -1,
                "ModulePath":  None
            })

            self.remote_log[process.pid].update(
            {
                    #"index": index,
                    "syscall": syscall.name,
                    "sucess": success,
                    "result": syscall.result_text,
                    "args": arg_list
            })
            log.info(self.remote_log[process.pid])

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2:
            print "Usage: tracer.py <program> [<args>]"
            sys.exit(1)

        tracer = SyscallTracer(sys.argv[1])
        tracer.start()

    except KeyboardInterrupt:
        tracer.stop()
