# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import socket
import struct
import random
import pkgutil
import logging
import hashlib
import xmlrpclib
import traceback
from ctypes import create_unicode_buffer, create_string_buffer
from ctypes import c_wchar_p, byref, c_int, sizeof
from threading import Lock, Thread
from datetime import datetime

from lib.api.process import Process
from lib.common.abstracts import Package, Auxiliary
from lib.common.constants import PATHS, PIPE
from lib.common.defines import KERNEL32
from lib.common.defines import ERROR_MORE_DATA, ERROR_PIPE_CONNECTED
from lib.common.defines import PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE
from lib.common.defines import PIPE_READMODE_MESSAGE, PIPE_WAIT
from lib.common.defines import PIPE_UNLIMITED_INSTANCES, INVALID_HANDLE_VALUE
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.results import upload_to_host
from lib.core.config import Config
from lib.core.packages import choose_package
from lib.core.privileges import grant_debug_privilege
from lib.core.startup import create_folders, init_logging
from modules import auxiliary

log = logging.getLogger()

BUFSIZE = 512
FILES_LIST = []
DUMPED_LIST = []
PROCESS_LIST = []
PROCESS_LOCK = Lock()
DEFAULT_DLL = None

PID = os.getpid()
PPID = Process(pid=PID).get_parent_pid()

# this is still preparation status - needs finalizing
def protected_filename(fname):
    """Checks file name against some protected names."""
    if not fname:
        return False

    protected_names = []
    for name in protected_names:
        if name in fname:
            return True

    return False

def add_pid(pid):
    """Add a process to process list."""
    if type(pid) == long or type(pid) == int or type(pid) == str:
        log.info("Added new process to list with pid: %s", pid)
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
        log.info("Added new file to list with path: %s",
                 unicode(file_path).encode("utf-8", "replace"))
        FILES_LIST.append(file_path)

def dump_file(file_path):
    """Create a copy of the give file path."""
    try:
        if os.path.exists(file_path):
            sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            if sha256 in DUMPED_LIST:
                # The file was already dumped, just skip.
                return
        else:
            log.warning("File at path \"%s\" does not exist, skip", file_path)
            return
    except IOError as e:
        log.warning("Unable to access file at path \"%s\": %s", file_path, e)
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

    upload_path = os.path.join("files",
                               str(random.randint(100000000, 9999999999)),
                               file_name)
    try:
        upload_to_host(file_path, upload_path)
        DUMPED_LIST.append(sha256)
    except (IOError, socket.error) as e:
        log.error("Unable to upload dropped file at path \"%s\": %s",
                  file_path, e)


def del_file(fname):
    dump_file(fname)

    # Filenames are case-insenstive in windows.
    fnames = [x.lower() for x in FILES_LIST]

    # If this filename exists in the FILES_LIST, then delete it, because it
    # doesn't exist anymore anyway.
    if fname.lower() in fnames:
        FILES_LIST.pop(fnames.index(fname.lower()))

def move_file(old_fname, new_fname):
    # Filenames are case-insenstive in windows.
    fnames = [x.lower() for x in FILES_LIST]

    # Check whether the old filename is in the FILES_LIST
    if old_fname.lower() in fnames:

        # Get the index of the old filename
        idx = fnames.index(old_fname.lower())

        # Replace the old filename by the new filename
        FILES_LIST[idx] = new_fname

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
        wait = False
        proc = None

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

            # Parse the prefix for the received notification.
            # In case of GETPIDS we're gonna return the current process ID
            # and the process ID of our parent process (agent.py).
            if command == "GETPIDS":
                response = struct.pack("II", PID, PPID)

            # When analyzing we don't want to hook all functions, as we're
            # having some stability issues with regards to webbrowsers.
            elif command == "HOOKDLLS":
                is_url = Config(cfg="analysis.conf").category != "file"

                url_dlls = "ntdll", "kernel32"

                def hookdll_encode(names):
                    # We have to encode each dll name as unicode string
                    # with length 16.
                    names = [name + "\x00" * (16-len(name)) for name in names]
                    f = lambda s: "".join(ch + "\x00" for ch in s)
                    return "".join(f(name) for name in names)

                # If this sample is not a URL, then we don't want to limit
                # any API hooks (at least for now), so we write a null-byte
                # which indicates that all DLLs should be hooked.
                if not is_url:
                    response = "\x00"
                else:
                    response = hookdll_encode(url_dlls)

            # In case of PID, the client is trying to notify the creation of
            # a new process to be injected and monitored.
            elif command.startswith("PROCESS:"):
                # We acquire the process lock in order to prevent the analyzer
                # to terminate the analysis while we are operating on the new
                # process.
                PROCESS_LOCK.acquire()

                # Set the current DLL to the default one provided
                # at submission.
                dll = DEFAULT_DLL

                # We parse the process ID.
                data = command[8:]
                process_id = thread_id = None
                if not "," in data:
                    if data.isdigit():
                        process_id = int(data)
                elif len(data.split(",")) == 2:
                    process_id, param = data.split(",")
                    thread_id = None
                    if process_id.isdigit():
                        process_id = int(process_id)
                    else:
                        process_id = None

                    if param.isdigit():
                        thread_id = int(param)
                    else:
                        # XXX: Expect a new DLL as a message parameter?
                        if isinstance(param, str):
                            dll = param

                if process_id:
                    if process_id not in (PID, PPID):
                        # We inject the process only if it's not being
                        # monitored already, otherwise we would generated
                        # polluted logs.
                        if process_id not in PROCESS_LIST:
                            # Open the process and inject the DLL.
                            # Hope it enjoys it.
                            proc = Process(pid=process_id,
                                           thread_id=thread_id)

                            filepath = proc.get_filepath()
                            filename = os.path.basename(filepath)

                            log.info("Announced process name: %s", filename)

                            if not protected_filename(filename):
                                # Add the new process ID to the list of
                                # monitored processes.
                                add_pids(process_id)

                                # If we have both pid and tid, then we can use
                                # apc to inject
                                if process_id and thread_id:
                                    proc.inject(dll, apc=True)
                                else:
                                    # we inject using CreateRemoteThread, this
                                    # needs the waiting in order to make sure
                                    # no race conditions occur
                                    proc.inject(dll)
                                    wait = True

                                log.info("Successfully injected process with "
                                         "pid %s", proc.pid)
                    else:
                        log.warning("Received request to inject Cuckoo "
                                    "processes, skip")

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
            elif command.startswith("FILE_MOVE:"):
                # syntax = FILE_MOVE:old_file_path::new_file_path
                if "::" in command[10:]:
                    old_fname, new_fname = command[10:].split("::", 1)
                    move_file(old_fname.decode("utf-8"),
                              new_fname.decode("utf-8"))

        KERNEL32.WriteFile(self.h_pipe,
                           create_string_buffer(response),
                           len(response),
                           byref(bytes_read),
                           None)

        KERNEL32.CloseHandle(self.h_pipe)

        # We wait until cuckoomon reports back.
        if wait:
            proc.wait()

        if proc:
            proc.close()

        return True

class PipeServer(Thread):
    """Cuckoo PIPE server.

    This Pipe Server receives notifications from the injected processes for
    new processes being spawned and for files being created or deleted.
    """

    def __init__(self, pipe_name=PIPE):
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
                                               PIPE_TYPE_MESSAGE |
                                               PIPE_READMODE_MESSAGE |
                                               PIPE_WAIT,
                                               PIPE_UNLIMITED_INSTANCES,
                                               BUFSIZE,
                                               BUFSIZE,
                                               0,
                                               None)

            if h_pipe == INVALID_HANDLE_VALUE:
                return False

            # If we receive a connection to the pipe, we invoke the handler.
            if KERNEL32.ConnectNamedPipe(h_pipe, None) or KERNEL32.GetLastError() == ERROR_PIPE_CONNECTED:
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
    PIPE_SERVER_COUNT = 4

    def __init__(self):
        self.pipes = [None]*self.PIPE_SERVER_COUNT
        self.config = None
        self.target = None

    def prepare(self):
        """Prepare env for analysis."""
        global DEFAULT_DLL

        # Get SeDebugPrivilege for the Python process. It will be needed in
        # order to perform the injections.
        grant_debug_privilege()

        # Create the folders used for storing the results.
        create_folders()

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")

        # Set virtual machine clock.
        clock = datetime.strptime(self.config.clock, "%Y%m%dT%H:%M:%S")
        # Setting date and time.
        # NOTE: Windows system has only localized commands with date format
        # following localization settings, so these commands for english date
        # format cannot work in other localizations.
        # In addition DATE and TIME commands are blocking if an incorrect
        # syntax is provided, so an echo trick is used to bypass the input
        # request and not block analysis.
        os.system("echo:|date {0}".format(clock.strftime("%m-%d-%y")))
        os.system("echo:|time {0}".format(clock.strftime("%H:%M:%S")))

        # Set the default DLL to be used by the PipeHandler.
        DEFAULT_DLL = self.get_options().get("dll", None)

        # Initialize and start the Pipe Servers. This is going to be used for
        # communicating with the injected and monitored processes.
        for x in xrange(self.PIPE_SERVER_COUNT):
            self.pipes[x] = PipeServer()
            self.pipes[x].daemon = True
            self.pipes[x].start()

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(os.environ["TEMP"] + os.sep,
                                       str(self.config.file_name))
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
                log.warning("Failed parsing the options: %s", e)
            else:
                for field in fields:
                    # Split the name and the value of the option.
                    try:
                        key, value = field.strip().split("=")
                    except ValueError as e:
                        log.warning("Failed parsing option (%s): %s", field, e)
                    else:
                        # If the parsing went good, we add the option to the
                        # dictionary.
                        options[key.strip()] = value.strip()

        return options

    def complete(self):
        """End analysis."""
        # Stop the Pipe Servers.
        for x in xrange(self.PIPE_SERVER_COUNT):
            self.pipes[x].stop()
        # Dump all the notified files.
        dump_files()
        # Hell yeah.
        log.info("Analysis completed")

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        log.info("Starting analyzer from: %s", os.getcwd())
        log.info("Storing results at: %s", PATHS["root"])
        log.info("Pipe server name: %s", PIPE)

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
                raise CuckooError("No valid package available for file "
                                  "type: {0}".format(self.config.file_type))

            log.info("Automatically selected analysis package \"%s\"", package)
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
            raise CuckooError("Unable to import package \"{0}\", does "
                              "not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract's subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class "
                              "(package={0}): {1}".format(package_name, e))

        # Initialize the analysis package.
        pack = package_class(self.get_options())

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled = []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module()
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
                continue
            finally:
                log.info("Started auxiliary module %s",
                         aux.__class__.__name__)
                aux_enabled.append(aux)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(self.target)
        except NotImplementedError:
            raise CuckooError("The package \"{0}\" doesn't contain a run "
                              "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooError("The package \"{0}\" start function raised an "
                              "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooError("The package \"{0}\" start function encountered "
                              "an unhandled exception: "
                              "{1}".format(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True
        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running "
                     "for the full timeout")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout")
            pid_check = False

        time_counter = 0

        while True:
            time_counter += 1
            if time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis")
                break

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
                            log.info("Process with pid %s has terminated", pid)
                            PROCESS_LIST.remove(pid)

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if len(PROCESS_LIST) == 0:
                        log.info("Process list is empty, "
                                 "terminating analysis...")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the "
                                 "termination of the analysis...")
                        break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning("The package \"%s\" check function raised "
                                "an exception: %s", package_name, e)
            finally:
                # Zzz.
                KERNEL32.Sleep(1000)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        # Terminate the Auxiliary modules.
        for aux in aux_enabled:
            try:
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s",
                            aux.__class__.__name__, e)

        # Try to terminate remaining active processes. We do this to make sure
        # that we clean up remaining open handles (sockets, files, etc.).
        log.info("Terminating remaining processes before shutdown...")

        for pid in PROCESS_LIST:
            proc = Process(pid=pid)
            if proc.is_alive():
                try:
                    proc.terminate()
                except:
                    continue

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
    # weill notify the agent of the failure. Also catched unexpected
    # exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers) > 0:
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        server.complete(success, error, PATHS["root"])
