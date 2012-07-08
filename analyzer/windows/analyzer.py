# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import shutil
import logging
import xmlrpclib
import ConfigParser
from ctypes import *
from threading import Lock, Thread, Timer

from lib.api.process import Process
from lib.common.exceptions import CuckooError
from lib.common.abstracts import Package
from lib.common.defines import *
from lib.common.paths import PATHS
from lib.core.config import Config
from lib.core.startup import create_folders, init_logging
from lib.core.privileges import grant_debug_privilege
from lib.core.packages import choose_package
from lib.core.screenshots import Screenshots

log = logging.getLogger()

BUFSIZE = 512
FILES_LIST = []
PROCESS_LIST = []
PROCESS_LOCK = Lock()

def add_file(file_path):
    """Add a file to file list."""
    if file_path.startswith("\\\\.\\"):
        return

    if file_path.startswith("\\??\\"):
        file_path = file_path[4:]

    if os.path.exists(file_path):
        if file_path not in FILES_LIST:
            log.info("Added new file to list with path: %s" % file_path)
            FILES_LIST.append(file_path)

def add_pid(pid):
    """Add a process to process list."""
    PROCESS_LOCK.acquire()

    if type(pid) == long or type(pid) == int or type(pid) == str:
        log.info("Added new process to list with pid: %d" % pid)
        PROCESS_LIST.append(pid)

    PROCESS_LOCK.release()

def add_pids(pids):
    """Add PID."""
    if type(pids) == list:
        for pid in pids:
            add_pid(pid)
    else:
        add_pid(pids)

def dump_files():
    """Dump dropped file."""
    for file_path in FILES_LIST:
        try:
            shutil.copy(file_path, PATHS["files"])
            log.info("Dropped file \"%s\" dumped successfully" % file_path)
        except (IOError, shutil.Error) as e:
            log.error("Unable to dump dropped file at path \"%s\": %s" % (file_path, e.message))

class PipeHandler(Thread):
    """PIPE handler, reads on PIPE."""

    def __init__(self, h_pipe):
        """@param h_pipe: PIPE to read."""
        Thread.__init__(self)
        self.h_pipe = h_pipe

    def run(self):
        """Run handler.
        @return: operation status.
        """
        data = ""

        while True:
            bytes_read = c_int(0)

            buf = create_string_buffer(BUFSIZE)
            success = KERNEL32.ReadFile(self.h_pipe,
                                        buf,
                                        sizeof(buf),
                                        byref(bytes_read),
                                        None)

            data += buf.value

            if not success and KERNEL32.GetLastError() == ERROR_MORE_DATA:
                continue
            #elif not success or bytes_read.value == 0:
            #    if KERNEL32.GetLastError() == ERROR_BROKEN_PIPE:
            #        pass
            
            break

        if data:
            command = data.strip()

            if command.startswith("PID:"):
                pid = command[4:]
                if pid.isdigit():
                    pid = int(pid)
                    if pid not in PROCESS_LIST:
                        add_pids(pid)
                        proc = Process(pid=pid)
                        proc.inject()
                        KERNEL32.WriteFile(self.h_pipe,
                                           create_string_buffer("OK"),
                                           2,
                                           byref(bytes_read),
                                           None)
            elif command.startswith("FILE:"):
                file_path = command[5:]
                add_file(file_path)

        return True

class PipeServer(Thread):
    """Cuckoo PIPE server."""

    def __init__(self, pipe_name = "\\\\.\\pipe\\cuckoo"):
        """@param pipe_name: Cuckoo PIPE server name."""
        Thread.__init__(self)
        self.pipe_name = pipe_name
        self.do_run = True

    def stop(self):
        """Stop PIPE server."""
        self.do_run = False

    def run(self):
        """Create and run PIPE server.
        @return: operation status.
        """
        while self.do_run:
            h_pipe = KERNEL32.CreateNamedPipeA(self.pipe_name,
                                               PIPE_ACCESS_DUPLEX,
                                               PIPE_TYPE_MESSAGE | \
                                               PIPE_READMODE_MESSAGE | \
                                               PIPE_WAIT,
                                               PIPE_UNLIMITED_INSTANCES,
                                               BUFSIZE,
                                               BUFSIZE,
                                               0,
                                               None)

            if h_pipe == INVALID_HANDLE_VALUE:
                return False

            if KERNEL32.ConnectNamedPipe(h_pipe, None):
                handler = PipeHandler(h_pipe)
                handler.daemon = True
                handler.start()
            else:
                KERNEL32.CloseHandle(h_pipe)

        return True

class Analyzer:
    """Cuckoo analyzer. Runs in guest and perform sample analysis."""

    def __init__(self):
        self.do_run = True
        self.pipe = None
        self.config = None
        self.file_path = None

    def prepare(self):
        """Prepare env for analysis."""
        grant_debug_privilege()
        create_folders()
        init_logging()
        self.config = Config(cfg=os.path.join(PATHS["root"], "analysis.conf"))
        self.pipe = PipeServer()
        self.pipe.daemon = True
        self.pipe.start()
        self.file_path = os.path.join(os.environ["SYSTEMDRIVE"] + os.sep, self.config.file_name)

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        options = {}
        if not self.config.options:
            try:
                fields = self.config.options.strip().split(",")
                for field in fields:
                    try:
                        key, value = field.strip().split("=")
                    except ValueError:
                        continue
                    options[key.strip()] = value.strip()
            except ValueError:
                pass

        return options

    def complete(self):
        """End analysis."""
        self.pipe.stop()
        dump_files()
        log.info("Analysis completed")

    def stop(self):
        """Stop analysis process."""
        self.do_run = False

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        if not self.config.package:
            log.info("No analysis package specified, trying to detect it automagically")
            package = choose_package(self.config.file_type)
            if not package:
                raise CuckooError("No valid package available for file type: %s" % self.config.file_type)
            else:
                log.info("Automatically selected analysis package \"%s\"" % package)
        else:
            package = self.config.package

        package_name = "packages.%s" % package

        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        except ImportError:
            raise CuckooError("Unable to import package \"%s\", does not exist." % package_name)

        Package()

        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class (package=%s): %s" % (package_name, e.message))
        
        pack = package_class(self.get_options())

        timer = Timer(self.config.timeout, self.stop)
        timer.start()
        
        shots = Screenshots()
        shots.start()

        try:
            pids = pack.start(self.file_path)
        except NotImplementedError:
            raise CuckooError("The package \"%s\" doesn't contain a run function." % package_name)

        add_pids(pids)

        while self.do_run:
            PROCESS_LOCK.acquire()

            try:
                for pid in PROCESS_LIST:
                    if not Process(pid=pid).is_alive():
                        log.info("Process with pid %d has terminated" % pid)
                        PROCESS_LIST.remove(pid)

                if len(PROCESS_LIST) == 0:
                    timer.cancel()
                    break

                try:
                    if not pack.check():
                        timer.cancel()
                        break
                except NotImplementedError:
                    pass
            finally:
                PROCESS_LOCK.release()
                KERNEL32.Sleep(1000)

        try:
            pack.finish()
        except NotImplementedError:
            pass

        shots.stop()
        self.complete()

        return True

if __name__ == "__main__":
    success = False
    error = ""

    try:
        analyzer = Analyzer()
        success = analyzer.run()
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"
    except CuckooError as e:
        error = e.message
        if len(log.handlers) > 0:
            log.critical(error)
        else:
            sys.stderr.write("%s\n" % e.message)
    finally:
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        if error:
            server.complete(success, error)
        else:
            server.complete(success)
