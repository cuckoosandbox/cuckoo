# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import random
import shutil
import pkgutil
import logging
import xmlrpclib
import ConfigParser
from ctypes import *
from threading import Lock, Thread, Timer

from lib.api.process import Process
from lib.common.exceptions import CuckooError
from lib.common.abstracts import Package, Auxiliary
from lib.common.defines import *
from lib.common.paths import PATHS
from lib.core.config import Config
from lib.core.startup import create_folders, init_logging
from lib.core.privileges import grant_debug_privilege
from lib.core.packages import choose_package
import modules.auxiliaries as auxiliaries

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
            log.info("Added new file to list with path: %s" % unicode(file_path).encode("utf-8", "replace"))
            FILES_LIST.append(file_path)

def add_pid(pid):
    """Add a process to process list."""

    if type(pid) == long or type(pid) == int or type(pid) == str:
        log.info("Added new process to list with pid: %d" % pid)
        PROCESS_LIST.append(pid)

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
        file_name = os.path.basename(file_path)

        while True:
            dir_path = os.path.join(PATHS["files"], str(random.randint(100000000, 9999999999)))
            if os.path.exists(dir_path):
                continue

            try:
                os.mkdir(dir_path)
                dump_path = os.path.join(dir_path, "%s.bin" % file_name)
            except OSError as e:
                dump_path = os.path.join(PATHS["files"], "%s.bin" % file_name)

            break

        try:
            shutil.copy(file_path, dump_path)
            log.info("Dropped file \"%s\" dumped successfully to path \"%s\"" % (file_path, dump_path))
        except (IOError, shutil.Error) as e:
            log.error("Unable to dump dropped file at path \"%s\": %s" % (file_path, e))

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
            #log.debug("Connection received (data=%s)" % command)

            if command.startswith("PID:"):
                PROCESS_LOCK.acquire()
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
                PROCESS_LOCK.release()
            elif command.startswith("FILE:"):
                file_path = command[5:]
                add_file(file_path)

        KERNEL32.CloseHandle(self.h_pipe)
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
        self.file_path = os.path.join(os.environ["TEMP"] + os.sep, self.config.file_name)

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        options = {}
        if self.config.options:
            try:
                fields = self.config.options.strip().split(",")
                for field in fields:
                    try:
                        key, value = field.strip().split("=")
                    except ValueError as e:
                        log.warning("Failed parsing option (%s): %s" % (field, e))
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

        package_name = "modules.packages.%s" % package

        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        except ImportError:
            raise CuckooError("Unable to import package \"%s\", does not exist." % package_name)

        Package()

        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class (package=%s): %s" % (package_name, e))
        
        pack = package_class(self.get_options())

        timer = Timer(self.config.timeout, self.stop)
        timer.start()

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliaries.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliaries.__path__, prefix):
            if ispkg:
                continue

            __import__(name, globals(), locals(), ["dummy"], -1)

        aux_enabled = []
        for auxiliary in Auxiliary.__subclasses__():
            try:
                aux = auxiliary()
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented" % aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s" % (aux.__class__.__name__, e))
                continue
            finally:
                aux_enabled.append(aux)

        # Start analysis package
        try:
            pids = pack.start(self.file_path)
        except NotImplementedError:
            raise CuckooError("The package \"%s\" doesn't contain a run function." % package_name)

        add_pids(pids)

        self.do_run = True

        while self.do_run:
            if PROCESS_LOCK.locked():
                KERNEL32.Sleep(1000)
                continue

            try:
                for pid in PROCESS_LIST:
                    if not Process(pid=pid).is_alive():
                        log.info("Process with pid %d has terminated" % pid)
                        PROCESS_LIST.remove(pid)

                if len(PROCESS_LIST) == 0:
                    log.info("Process list is empty, terminating analysis...")
                    timer.cancel()
                    break

                pack.set_pids(PROCESS_LIST)

                try:
                    if not pack.check():
                        log.info("The analysis package requested the termination of the analysis...")
                        timer.cancel()
                        break
                except NotImplementedError:
                    pass
            finally:
                KERNEL32.Sleep(1000)

        try:
            pack.finish()
        except NotImplementedError:
            pass

        # Terminate Auxiliary modules
        for aux in aux_enabled:
            try:
                aux.stop()
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s" % (aux.__class__.__name__, e))
                pass

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
        error = e
        if len(log.handlers) > 0:
            log.critical(error)
        else:
            sys.stderr.write("%s\n" % e)
    finally:
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        if error:
            server.complete(success, error)
        else:
            server.complete(success)
