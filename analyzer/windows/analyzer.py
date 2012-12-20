# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import struct
import random
import shutil
import pkgutil
import logging
import hashlib
import xmlrpclib
from ctypes import *
from threading import Lock, Thread, Timer

from lib.api.process import Process
from lib.common.exceptions import CuckooError, CuckooPackageError
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
DUMPED_LIST = []
PROCESS_LIST = []
PROCESS_LOCK = Lock()

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

def add_file(file_path):
    """Add a file to file list."""
    if file_path not in FILES_LIST:
        log.info("Added new file to list with path: %s"
                    % unicode(file_path).encode("utf-8", "replace"))
        FILES_LIST.append(file_path)

def dump_file(file_path):
    """Create a copy of the give file path."""
    if os.path.exists(file_path):
        sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
        if sha256 in DUMPED_LIST:
            # The file was already dumped, just skip.
            return
    else:
        log.warning("File at path \"%s\" does not exist, skip" % file_path)
        return

    # 32k is the maximum length for a filename
    path = create_unicode_buffer(32 * 1024)
    name = c_wchar_p()
    KERNEL32.GetFullPathNameW(file_path, 32 * 1024, path, byref(name))
    file_path = path.value
    
    # Check if the path has a valid file name, otherwise it's a directory
    # and we should abort the dump.
    if name.value:
        # Should be able to extract Alternate Data Streams names too.
        file_name = name.value[name.value.find(":")+1:]
    else:
        return

    while True:
        dir_path = os.path.join(PATHS["files"],
                                str(random.randint(100000000, 9999999999)))
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
        DUMPED_LIST.append(sha256)
        log.info("Dropped file \"%s\" dumped successfully to path \"%s\""
                  % (file_path, dump_path))
    except (IOError, shutil.Error) as e:
        log.error("Unable to dump dropped file at path \"%s\": %s"
                  % (file_path, e))

def del_file(fname):
    dump_file(fname)

    # Filenames are case-insenstive in windows.
    fnames = [x.lower() for x in FILES_LIST]

    # If this filename exists in the FILES_LIST, then delete it, because it
    # doesn't exist anymore anyway.
    if fname.lower() in fnames:
        FILES_LIST.pop(fnames.index(fname.lower()))

def dump_files():
    """Dump all the dropped files."""
    for file_path in FILES_LIST:
        dump_file(file_path)

class PipeHandler(Thread):
    """Pipe Handler.

    This class handles the notifications received through the Pipe Server and
    decides what to do with them.
    """

    def __init__(self, h_pipe):
        """@param h_pipe: PIPE to read."""
        Thread.__init__(self)
        self.h_pipe = h_pipe

    def run(self):
        """Run handler.
        @return: operation status.
        """
        data = ""
        response = "OK"

        # Read the data submitted to the Pipe Server.
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

            wait = False

            # Parse the prefix for the received notification.
            # In case of GETPIDS we're gonna return the current process ID
            # and the process ID of our parent process (agent.py).
            if command == "GETPIDS":
                pid = os.getpid()
                ppid = Process(pid=pid).get_parent_pid()
                response = struct.pack("II", pid, ppid)
            # In case of PID, the client is trying to notify the creation of
            # a new process to be injected and monitored.
            elif command.startswith("PROCESS:"):
                # We acquire the process lock in order to prevent the analyzer
                # to terminate the analysis while we are operating on the new
                # process.
                PROCESS_LOCK.acquire()

                # We parse the process ID.
                data = command[8:]

                process_id = thread_id = None
                if not "," in data:
                    if data.isdigit():
                        process_id = int(data)
                elif len(data.split(",")) == 2:
                    process_id, thread_id = data.split(",")
                    if process_id.isdigit():
                        process_id = int(process_id)
                    else:
                        process_id = None

                    if thread_id.isdigit():
                        thread_id = int(thread_id)
                    else:
                        thread_id = None

                if process_id:
                    if process_id != os.getpid():
                        # We inject the process only if it's not being monitored
                        # already, otherwise we would generated polluted logs.
                        if process_id not in PROCESS_LIST:
                            # Add the new process ID to the list of monitored
                            # processes.
                            add_pids(process_id)

                            # Open the process and inject the DLL.
                            # Hope it enjoys it.
                            proc = Process(pid=process_id,
                                           thread_id=thread_id)

                            # if we have both pid and tid, then we can use
                            # apc to inject
                            if process_id and thread_id:
                                proc.inject(apc=True)
                            else:
                                proc.inject()

                            # we have to wait because we use the
                            # CreateRemoteThread injection method
                            wait = True
                    else:
                        log.warning("Received request to inject myself, skip")

                # Once we're done operating on the processes list, we release
                # the lock.
                PROCESS_LOCK.release()
            # In case of FILE_NEW, the client is trying to notify the creation
            # of a new file.
            elif command.startswith("FILE_NEW:"):
                # We extract the file path.
                file_path = command[9:].decode("utf-8")
                # We add the file to the list.
                add_file(file_path)
            # In case of FILE_DEL, the client is trying to notify an ongoing
            # deletion of an existing file, therefore we need to dump it
            # straight away.
            elif command.startswith("FILE_DEL:"):
                # Extract the file path.
                file_path = command[9:].decode("utf-8")
                # Dump the file straight away.
                del_file(file_path)

        # we wait until cuckoomon reports back, so we know for sure that
        # cuckoomon has finished initializing etc
        if wait:
            proc.wait()
            log.info("Successfully injected process with pid %d" % proc.pid)

        KERNEL32.WriteFile(self.h_pipe,
                           create_string_buffer(response),
                           len(response),
                           byref(bytes_read),
                           None)

        KERNEL32.CloseHandle(self.h_pipe)

        return True

class PipeServer(Thread):
    """Cuckoo PIPE server.

    This Pipe Server receives notifications from the injected processes for
    new processes being spawned and for files being created or deleted.
    """

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
            # Create the Named Pipe.
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

            # If we receive a connection to the pipe, we invoke the handler.
            if KERNEL32.ConnectNamedPipe(h_pipe, None):
                handler = PipeHandler(h_pipe)
                handler.daemon = True
                handler.start()
            else:
                KERNEL32.CloseHandle(h_pipe)

        return True

class Analyzer:
    """Cuckoo Windows Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including handling of the pipe server, the auxiliary modules and
    the analysis packages.
    """

    def __init__(self):
        self.do_run = True
        self.pipe = None
        self.config = None
        self.target = None

    def prepare(self):
        """Prepare env for analysis."""
        # Get SeDebugPrivilege for the Python process. It will be needed in
        # order to perform the injections.
        grant_debug_privilege()

        # Create the folders used for storing the results.
        create_folders()

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg=os.path.join(PATHS["root"], "analysis.conf"))

        # Initialize and start the Pipe Server. This is going to be used for
        # communicating with the injected and monitored processes.
        self.pipe = PipeServer()
        self.pipe.daemon = True
        self.pipe.start()

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(os.environ["TEMP"] + os.sep,
                                       self.config.file_name)
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        #
        # Here we parse such options and provide a dictionary that will be made
        # accessible to the analysis package.
        options = {}
        if self.config.options:
            try:
                # Split the options by comma.
                fields = self.config.options.strip().split(",")
            except ValueError as e:
                log.warning("Failed parsing the options: %s" % e)
            else:
                for field in fields:
                    # Split the name and the value of the option.
                    try:
                        key, value = field.strip().split("=")
                    except ValueError as e:
                        log.warning("Failed parsing option (%s): %s"
                                    % (field, e))
                    else:
                        # If the parsing went good, we add the option to the
                        # dictionary.
                        options[key.strip()] = value.strip()

        return options

    def complete(self):
        """End analysis."""
        # Stop the Pipe Server.
        self.pipe.stop()
        # Dump all the notified files.
        dump_files()
        # Hell yeah.
        log.info("Analysis completed")

    def stop(self):
        """Stop analysis process."""
        self.do_run = False

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.info("No analysis package specified, trying to detect "
                     "it automagically")
            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(self.config.file_type, self.config.file_name)
            # If it's an URL, we'll just use the default Internet Explorer
            # package.
            else:
                package = "ie"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file type: %s"
                                  % self.config.file_type)
            else:
                log.info("Automatically selected analysis package \"%s\""
                         % package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError("Unable to import package \"%s\", does not exist."
                              % package_name)

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract's subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class (package=%s): %s"
                              % (package_name, e))

        # Initialize the analysis package.
        pack = package_class(self.get_options())

        # Set the analysis timeout timer. When the timeout gets hit, we force
        # the termination of the analysis.
        timer = Timer(self.config.timeout, self.stop)
        timer.start()

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliaries.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliaries.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module \"%s\": %s"
                            % (name, e))

        # Walk through the available auxiliary modules.
        aux_enabled = []
        for auxiliary in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = auxiliary()
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented"
                            % aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s"
                            % (aux.__class__.__name__, e))
                continue
            finally:
                aux_enabled.append(aux)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(self.target)
        except NotImplementedError:
            raise CuckooError("The package \"%s\" doesn't contain a run "
                              "function." % package_name)
        except CuckooPackageError as e:
            raise CuckooError("The package \"%s\" start function raised an "
                              "error: %s" % (package_name, e))
        except Exception as e:
            raise CuckooError("The package \"%s\" start function encountered "
                              "an unhandled exception: %s" %(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True
        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running for "
                     "the full timeout")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout")
            pid_check = False

        self.do_run = True

        while self.do_run:
            # If the process lock is locked, it means that something is
            # operating on the list of monitored processes. Therefore we cannot
            # proceed with the checks until the lock is released.
            if PROCESS_LOCK.locked():
                KERNEL32.Sleep(1000)
                continue

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in PROCESS_LIST:
                        if not Process(pid=pid).is_alive():
                            log.info("Process with pid %d has terminated" % pid)
                            PROCESS_LIST.remove(pid)

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if len(PROCESS_LIST) == 0:
                        log.info("Process list is empty, terminating "
                                 "analysis...")
                        # Therefore we cancel the timer.
                        timer.cancel()
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal operations
                    # within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the "
                                 "termination of the analysis...")
                        # We cancel the timer.
                        timer.cancel()
                        break
                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning("The package \"%s\" check function raised "
                                "an exception: %s" % (package_name, e))
            finally:
                # Zzz.
                KERNEL32.Sleep(1000)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s" % (package_name, e))

        # Terminate the Auxiliary modules.
        for aux in aux_enabled:
            try:
                aux.stop()
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s"
                            % (aux.__class__.__name__, e))

        # Let's invoke the completion procedure.
        self.complete()

        return True

if __name__ == "__main__":
    success = False
    error = ""

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()
        # Run it and wait for the response.
        success = analyzer.run()
    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"
    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis
    # weill notify the agent of the failure.
    except CuckooError as e:
        # Store the error.
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers) > 0:
            log.critical(error)
        else:
            sys.stderr.write("%s\n" % e)
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        # If the analyzer returned an error, we report it.
        if error:
            server.complete(success, error)
        # Otherwise just complete.
        else:
            server.complete(success)
