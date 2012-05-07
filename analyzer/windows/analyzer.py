import os
import sys
import logging
import xmlrpclib
import ConfigParser
from ctypes import *
from threading import Lock, Thread, Timer

from lib.core.defines import *
from lib.core.paths import PATHS
from lib.api.process import Process
from lib.abstract.exceptions import CuckooError
from lib.abstract.package import Package
from lib.core.config import Config
from lib.core.startup import create_folders, init_logging
from lib.core.privileges import grant_debug_privilege

log = logging.getLogger()

BUFSIZE = 512
FILES_LIST = []
PROCESS_LIST = []
PROCESS_LOCK = Lock()

def add_file(file_path):
    if file_path.startswith("\\\\."):
        return

    if os.path.exists(file_path):
        if file_path not in FILES_LIST:
            log.info("Added new file to list with path: %s" % file_path)
            FILES_LIST.append(file_path)

def add_pid(pid):
    PROCESS_LOCK.acquire()

    if type(pid) == long or type(pid) == int or type(pid) == str:
        log.info("Added new process to list with pid: %d" % pid)
        PROCESS_LIST.append(pid)

    PROCESS_LOCK.release()

def add_pids(pids):
    if type(pids) == list:
        for pid in pids:
            add_pid(pid)
    else:
        add_pid(pids)

class PipeHandler(Thread):
    def __init__(self, h_pipe):
        Thread.__init__(self)
        self.h_pipe = h_pipe

    def run(self):
        data = create_string_buffer(BUFSIZE)

        while True:
            bytes_read = c_int(0)

            success = KERNEL32.ReadFile(self.h_pipe,
                                        data,
                                        sizeof(data),
                                        byref(bytes_read),
                                        None)

            if not success or bytes_read.value == 0:
                if KERNEL32.GetLastError() == ERROR_BROKEN_PIPE:
                    pass
                break

        if data:
            command = data.value.strip()
                
            if command.startswith("PID:"):
                pid = command[4:]
                if pid.isdigit():
                    pid = int(pid)
                    if pid not in PROCESS_LIST:
                        add_pids(pid)
                        proc = Process(pid=pid)
                        proc.inject()
            elif command.startswith("FILE:"):
                file_path = command[5:]
                add_file(file_path)

        return True

class PipeServer(Thread):
    def __init__(self, pipe_name = "\\\\.\\pipe\\cuckoo"):
        Thread.__init__(self)
        self.pipe_name = pipe_name
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
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
    def __init__(self):
        self.do_run = True
        self.pipe = None
        self.config = None
        self.file_path = None

    def prepare(self):
        grant_debug_privilege()
        create_folders()
        init_logging()
        self.config = Config(cfg=os.path.join(PATHS["root"], "analysis.conf"))
        self.pipe = PipeServer()
        self.pipe.daemon = True
        self.pipe.start()
        self.file_path = os.path.join(os.environ["SYSTEMDRIVE"] + os.sep, self.config.file_name)

    def complete(self):
        self.pipe.stop()
        log.info("Analysis completed")

    def stop(self):
        self.do_run = False

    def run(self):
        self.prepare()

        package_name = "packages.%s" % self.config.package

        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        except ImportError:
            raise CuckooError("Unable to import package \"%s\", does not exist." % package_name)

        Package()
        package_import = Package.__subclasses__()[0]
        pack = package_import()

        timer = Timer(120.0, self.stop)
        timer.start()

        try:
            pids = pack.run(self.file_path)
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