# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import socket
import struct
import pkgutil
import logging
import hashlib
import threading
import traceback
import urllib
import urllib2
import xmlrpclib
from datetime import datetime

from lib.api.process import Process
from lib.common.abstracts import Package, Auxiliary
from lib.common.constants import PATHS, SHUTDOWN_MUTEX
from lib.common.defines import KERNEL32
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.rand import random_string
from lib.common.results import upload_to_host
from lib.core.config import Config
from lib.core.packages import choose_package
from lib.core.pipe import PipeServer, PipeForwarder, PipeDispatcher
from lib.core.privileges import grant_debug_privilege
from lib.core.startup import create_folders, init_logging
from modules import auxiliary

log = logging.getLogger("analyzer")

class Files(object):
    PROTECTED_NAMES = ()

    def __init__(self):
        self.files = []
        self.dumped = []

    def is_protected_filename(self, file_name):
        """Do we want to inject into a process with this name?"""
        return file_name.lower() in self.PROTECTED_NAMES

    def add_file(self, filepath):
        """Add filepath to the list of files."""
        if filepath.lower() not in self.files:
            log.info("Added new file to list with path: %s", filepath)
            self.files.append(filepath.lower())

    def dump_file(self, filepath):
        """Dump a file to the host."""
        if not os.path.isfile(filepath):
            log.warning("File at path \"%r\" does not exist, skip.", filepath)
            return False

        # Check whether we've already dumped this file - in that case skip it.
        try:
            sha256 = hash_file(hashlib.sha256, filepath)
            if sha256 in self.dumped:
                return
        except IOError as e:
            log.info("Error dumping file from path \"%s\": %s", filepath, e)
            return

        filename = "%s_%s" % (sha256[:16], os.path.basename(filepath))
        upload_path = os.path.join("files", filename)

        try:
            upload_to_host(filepath, upload_path)
            self.dumped.append(sha256)
        except (IOError, socket.error) as e:
            log.error("Unable to upload dropped file at path \"%s\": %s",
                      filepath, e)

    def delete_file(self, filepath):
        """A file is about to removed and thus should be dumped right away."""
        self.dump_file(filepath)

        # Remove the filepath from the files list.
        if filepath.lower() in self.files:
            self.files.remove(filepath.lower())

    def move_file(self, oldfilepath, newfilepath):
        """A file will be moved - track this change."""
        if oldfilepath.lower() in self.files:
            # Replace the entry with the new filepath.
            index = self.files.index(oldfilepath.lower())
            self.files[index] = newfilepath.lower()

    def dump_files(self):
        """Dump all pending files."""
        for filepath in self.files:
            self.dump_file(filepath)

class ProcessList(object):
    def __init__(self):
        self.pids = []
        self.pids_notrack = []

    def add_pid(self, pid, track=True):
        """Add a process identifier to the process list.

        Track determines whether the analyzer should be monitoring this
        process, i.e., whether Cuckoo should wait for this process to finish.
        """
        if int(pid) not in self.pids and int(pid) not in self.pids_notrack:
            if track:
                self.pids.append(int(pid))
            else:
                self.pids_notrack.append(int(pid))

    def add_pids(self, pids):
        """Add one or more process identifiers to the process list."""
        if isinstance(pids, (tuple, list)):
            for pid in pids:
                self.add_pid(pid)
        else:
            self.add_pid(pids)

    def has_pid(self, pid, notrack=True):
        """Is this process identifier being tracked?"""
        if int(pid) in self.pids:
            return True

        if notrack and int(pid) in self.pids_notrack:
            return True

        return False

    def remove_pid(self, pid):
        """Remove a process identifier from being tracked."""
        if pid in self.pids:
            self.pids.remove(pid)

        if pid in self.pids_notrack:
            self.pids_notrack.remove(pid)

class CommandPipeHandler(object):
    """Pipe Handler.

    This class handles the notifications received through the Pipe Server and
    decides what to do with them.
    """
    ignore_list = dict(pid=[])

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def _handle_debug(self, data):
        """Debug message from the monitor."""
        log.debug(data)

    def _handle_info(self, data):
        """Regular message from the monitor."""
        log.info(data)

    def _handle_warning(self, data):
        """Warning message from the monitor."""
        log.warning(data)

    def _handle_critical(self, data):
        """Critical message from the monitor."""
        log.critical(data)

    def _handle_loaded(self, data):
        """The monitor has loaded into a particular process."""
        if not data or data.count(",") != 1:
            log.warning("Received loaded command with incorrect parameters, "
                        "skipping it.")
            return

        pid, track = data.split(",")
        if not pid.isdigit() or not track.isdigit():
            log.warning("Received loaded command with incorrect parameters, "
                        "skipping it.")
            return

        self.analyzer.process_lock.acquire()
        self.analyzer.process_list.add_pid(int(pid), track=int(track))
        self.analyzer.process_lock.release()

        log.debug("Loaded monitor into process with pid %s", pid)

    def _handle_getpids(self, data):
        """Return the process identifiers of the agent and its parent
        process."""
        return struct.pack("II", self.analyzer.pid, self.analyzer.ppid)

    def _inject_process(self, process_id, thread_id, mode):
        """Helper function for injecting the monitor into a process."""
        # We acquire the process lock in order to prevent the analyzer to
        # terminate the analysis while we are operating on the new process.
        self.analyzer.process_lock.acquire()

        # Set the current DLL to the default one provided at submission.
        dll = self.analyzer.default_dll

        if process_id in (self.analyzer.pid, self.analyzer.ppid):
            if process_id not in CommandPipeHandler.ignore_list["pid"]:
                log.warning("Received request to inject Cuckoo processes, "
                            "skipping it.")
                CommandPipeHandler.ignore_list["pid"].append(process_id)
            self.analyzer.process_lock.release()
            return

        # We inject the process only if it's not being monitored already,
        # otherwise we would generated polluted logs (if it wouldn't crash
        # horribly to start with).
        if self.analyzer.process_list.has_pid(process_id):
            # This pid is already on the notrack list, move it to the
            # list of tracked pids.
            if not self.analyzer.process_list.has_pid(process_id,
                                                      notrack=False):
                log.debug("Received request to inject pid=%d. It was already "
                          "on our notrack list, moving it to the track list.")

                self.analyzer.process_list.remove_pid(process_id)
                self.analyzer.process_list.add_pid(process_id)
                CommandPipeHandler.ignore_list["pid"].append(process_id)
            # Spit out an error once and just ignore it further on.
            elif process_id not in CommandPipeHandler.ignore_list["pid"]:
                log.debug("Received request to inject pid=%d, but we are "
                          "already injected there.", process_id)
                CommandPipeHandler.ignore_list["pid"].append(process_id)

            # We're done operating on the processes list, release the lock.
            self.analyzer.process_lock.release()
            return

        # Open the process and inject the DLL. Hope it enjoys it.
        proc = Process(pid=process_id, tid=thread_id)

        filename = os.path.basename(proc.get_filepath())

        if not self.analyzer.files.is_protected_filename(filename):
            # Add the new process ID to the list of monitored processes.
            self.analyzer.process_list.add_pid(process_id)

            # We're done operating on the processes list,
            # release the lock. Let the injection do its thing.
            self.analyzer.process_lock.release()

            # If we have both pid and tid, then we can use APC to inject.
            if process_id and thread_id:
                proc.inject(dll, apc=True, mode="%s" % mode)
            else:
                proc.inject(dll, apc=False, mode="%s" % mode)

            log.info("Injected into process with pid %s and name %s",
                     proc.pid, filename)

    def _handle_process(self, data):
        """Request for injection into a process."""
        # Parse the process identifier.
        if not data or not data.isdigit():
            log.warning("Received PROCESS command from monitor with an "
                        "incorrect argument.")
            return

        return self._inject_process(int(data), None, 0)

    def _handle_process2(self, data):
        """Request for injection into a process using APC."""
        # Parse the process and thread identifier.
        if not data or data.count(",") != 2:
            log.warning("Received PROCESS2 command from monitor with an "
                        "incorrect argument.")
            return

        pid, tid, mode = data.split(",")
        if not pid.isdigit() or not tid.isdigit() or not mode.isdigit():
            log.warning("Received PROCESS2 command from monitor with an "
                        "incorrect argument.")
            return

        return self._inject_process(int(pid), int(tid), int(mode))

    def _handle_file_new(self, data):
        """Notification of a new dropped file."""
        # Extract the file path and add it to the list.
        self.analyzer.files.add_file(data.decode("utf8"))

    def _handle_file_del(self, data):
        """Notification of a file being removed - we have to dump it before
        it's being removed."""
        self.analyzer.files.delete_file(data.decode("utf8"))

    def _handle_file_move(self, data):
        """A file is being moved - track these changes."""
        if "::" not in data:
            log.warning("Received FILE_MOVE command from monitor with an "
                        "incorrect argument.")
            return

        old_filepath, new_filepath = data.split("::", 1)
        self.analyzer.files.move_file(old_filepath.decode("utf8"),
                                      new_filepath.decode("utf8"))

    def dispatch(self, data):
        response = "NOPE"

        if not data or ":" not in data:
            log.critical("Unknown command received from the monitor: %r",
                         data.strip())
        else:
            command, arguments = data.strip().split(":", 1)

            if not hasattr(self, "_handle_%s" % command.lower()):
                log.critical("Unknown command received from the monitor: %r",
                             data.strip())
            else:
                fn = getattr(self, "_handle_%s" % command.lower())
                response = fn(arguments)

        return response

class Analyzer(object):
    """Cuckoo Windows Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including handling of the pipe server, the auxiliary modules and
    the analysis packages.
    """

    def __init__(self):
        self.config = None
        self.target = None
        self.do_run = True
        self.time_counter = 0

        self.process_lock = threading.Lock()
        self.default_dll = None
        self.pid = os.getpid()
        self.ppid = Process(pid=self.pid).get_parent_pid()
        self.files = Files()
        self.process_list = ProcessList()

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
        self.config = Config(cfg="analysis.conf")

        # Pass the configuration through to the Process class.
        Process.set_config(self.config)

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

        # Set the default DLL to be used for this analysis.
        self.default_dll = self.config.options.get("dll")

        # If a pipe name has not set, then generate a random one.
        if "pipe" in self.config.options:
            self.config.pipe = "\\\\.\\PIPE\\%s" % self.config.options["pipe"]
        else:
            self.config.pipe = "\\\\.\\PIPE\\%s" % random_string(16, 32)

        # Generate a random name for the logging pipe server.
        self.config.logpipe = "\\\\.\\PIPE\\%s" % random_string(16, 32)

        # Initialize and start the Command Handler pipe server. This is going
        # to be used for communicating with the monitored processes.
        self.command_pipe = PipeServer(PipeDispatcher, self.config.pipe,
                                       message=True,
                                       dispatcher=CommandPipeHandler(self))
        self.command_pipe.daemon = True
        self.command_pipe.start()

        # Initialize and start the Log Pipe Server - the log pipe server will
        # open up a pipe that monitored processes will use to send logs to
        # before they head off to the host machine.
        destination = self.config.ip, self.config.port
        self.log_pipe_server = PipeServer(PipeForwarder, self.config.logpipe,
                                          destination=destination)
        self.log_pipe_server.daemon = True
        self.log_pipe_server.start()

        # We update the target according to its category. If it's a file, then
        # we store the target path.
        if self.config.category == "file":
            self.target = os.path.join(os.environ["TEMP"] + os.sep,
                                       self.config.file_name)
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def stop(self):
        """Allows an auxiliary module to stop the analysis."""
        self.do_run = False

    def complete(self):
        """End analysis."""
        # Stop the Pipe Servers.
        self.command_pipe.stop()
        self.log_pipe_server.stop()

        # Dump all the notified files.
        self.files.dump_files()

        # Hell yeah.
        log.info("Analysis completed.")

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        log.debug("Starting analyzer from: %s", os.getcwd())
        log.debug("Storing results at: %s", PATHS["root"])
        log.debug("Pipe server name: %s", self.config.pipe)
        log.debug("Log pipe server name: %s", self.config.logpipe)

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.debug("No analysis package specified, trying to detect "
                      "it automagically.")

            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(self.config.file_type,
                                         self.config.file_name,
                                         self.config.pe_exports.split(","))
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

        # Enumerate the abstract subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class "
                              "(package={0}): {1}".format(package_name, e))

        # Initialize the analysis package.
        package = package_class(self.config.options)

        # Move the sample to the current working directory as provided by the
        # task - one is able to override the starting path of the sample.
        # E.g., for some samples it might be useful to run from %APPDATA%
        # instead of %TEMP%.
        if self.config.category == "file":
            self.target = package.move_curdir(self.target)

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
        aux_enabled, aux_avail = [], []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module(options=self.config.options, analyzer=self)
                aux_avail.append(aux)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
            else:
                log.debug("Started auxiliary module %s",
                          aux.__class__.__name__)
                aux_enabled.append(aux)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = package.start(self.target)
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

        # If the analysis package returned a list of process identifiers, we
        # add them to the list of monitored processes and enable the process monitor.
        if pids:
            self.process_list.add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running "
                     "for the full timeout.")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout.")
            pid_check = False

        while self.do_run:
            self.time_counter += 1
            if self.time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis.")
                break

            # If the process lock is locked, it means that something is
            # operating on the list of monitored processes. Therefore we
            # cannot proceed with the checks until the lock is released.
            if self.process_lock.locked():
                KERNEL32.Sleep(1000)
                continue

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in self.process_list.pids:
                        if not Process(pid=pid).is_alive():
                            log.info("Process with pid %s has terminated", pid)
                            self.process_list.remove_pid(pid)

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if not self.process_list.pids:
                        log.info("Process list is empty, "
                                 "terminating analysis.")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    package.set_pids(self.process_list.pids)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not package.check():
                        log.info("The analysis package requested the "
                                 "termination of the analysis.")
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

        if not self.do_run:
            log.debug("The analyzer has been stopped on request by an "
                      "auxiliary module.")

        # Create the shutdown mutex.
        KERNEL32.CreateMutexA(None, False, SHUTDOWN_MUTEX)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            package.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        try:
            # Upload files the package created to package_files in the
            # results folder.
            for path, name in package.package_files() or []:
                upload_to_host(path, os.path.join("package_files", name))
        except Exception as e:
            log.warning("The package \"%s\" package_files function raised an "
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

        if self.config.terminate_processes:
            # Try to terminate remaining active processes. We do this to make sure
            # that we clean up remaining open handles (sockets, files, etc.).
            log.info("Terminating remaining processes before shutdown.")

            for pid in self.process_list.pids:
                proc = Process(pid=pid)
                if proc.is_alive():
                    try:
                        proc.terminate()
                    except:
                        continue

        # Run the finish callback of every available Auxiliary module.
        for aux in aux_avail:
            try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary "
                            "module %s: %s", aux.__class__.__name__, e)

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

        data = {
            "status": "complete",
            "description": success,
        }
    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catch unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers):
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

        data = {
            "status": "exception",
            "description": error_exc,
        }
    finally:
        # Report that we're finished. First try with the XML RPC thing and
        # if that fails, attempt the new Agent.
        try:
            server = xmlrpclib.Server("http://127.0.0.1:8000")
            server.complete(success, error, PATHS["root"])
        except xmlrpclib.ProtocolError:
            urllib2.urlopen("http://127.0.0.1:8000/status",
                            urllib.urlencode(data)).read()
