# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import shutil
import logging
import Queue
from threading import Thread, Lock

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.plugins import list_plugins, RunAuxiliary, RunProcessing
from lib.cuckoo.core.plugins import RunSignatures, RunReporting
from lib.cuckoo.core.resultserver import Resultserver

log = logging.getLogger(__name__)

machinery = None
machine_lock = Lock()

total_analysis_count = 0
active_analysis_count = 0


class CuckooDeadMachine(Exception):
    """Exception thrown when a machine turns dead.

    When this exception has been thrown, the analysis task will start again,
    and will try to use another machine, when available.
    """
    pass


class AnalysisManager(Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(self, task, error_queue):
        """@param task: task object containing the details for the analysis."""
        Thread.__init__(self)
        Thread.daemon = True

        self.task = task
        self.errors = error_queue
        self.cfg = Config()
        self.storage = ""
        self.binary = ""
        self.machine = None

    def init_storage(self):
        """Initialize analysis storage folder."""
        self.storage = os.path.join(CUCKOO_ROOT,
                                    "storage",
                                    "analyses",
                                    str(self.task.id))

        # If the analysis storage folder already exists, we need to abort the
        # analysis or previous results will be overwritten and lost.
        if os.path.exists(self.storage):
            log.error("Analysis results folder already exists at path \"%s\","
                      " analysis aborted", self.storage)
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            log.error("Unable to create analysis folder %s", self.storage)
            return False

        return True

    def check_file(self):
        """Checks the integrity of the file to be analyzed."""
        sample = Database().view_sample(self.task.sample_id)

        sha256 = File(self.task.target).get_sha256()
        if sha256 != sample.sha256:
            log.error("Target file has been modified after submission: \"%s\"", self.task.target)
            return False

        return True

    def store_file(self):
        """Store a copy of the file being analyzed."""
        if not os.path.exists(self.task.target):
            log.error("The file to analyze does not exist at path \"%s\", "
                      "analysis aborted", self.task.target)
            return False

        sha256 = File(self.task.target).get_sha256()
        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)

        if os.path.exists(self.binary):
            log.info("File already exists at \"%s\"", self.binary)
        else:
            # TODO: do we really need to abort the analysis in case we are not
            # able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error) as e:
                log.error("Unable to store file from \"%s\" to \"%s\", "
                          "analysis aborted", self.task.target, self.binary)
                return False

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            if hasattr(os, "symlink"):
                os.symlink(self.binary, new_binary_path)
            else:
                shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            log.error("Unable to create symlink/copy from \"%s\" to "
                      "\"%s\": %s", self.binary, self.storage, e)

        return True

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None

        # Start a loop to acquire the a machine to run the analysis on.
        while True:
            machine_lock.acquire()

            # In some cases it's possible that we enter this loop without
            # having any available machines. We should make sure this is not
            # such case, or the analysis task will fail completely.
            if not machinery.availables():
                machine_lock.release()
                time.sleep(1)
                continue

            # If the user specified a specific machine ID, a platform to be
            # used or machine tags acquire the machine accordingly.
            try:
                machine = machinery.acquire(machine_id=self.task.machine,
                                            platform=self.task.platform,
                                            tags=self.task.tags)
            finally:
                machine_lock.release()

            # If no machine is available at this moment, wait for one second
            # and try again.
            if not machine:
                log.debug("Task #%d: no machine available yet", self.task.id)
                time.sleep(1)
            else:
                log.info("Task #%d: acquired machine %s (label=%s)",
                         self.task.id, machine.name, machine.label)
                break

        self.machine = machine

    def build_options(self):
        """Generate analysis options.
        @return: options dict.
        """
        options = {}

        options["id"] = self.task.id
        options["ip"] = self.machine.resultserver_ip
        options["port"] = self.machine.resultserver_port
        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["options"] = self.task.options
        options["enforce_timeout"] = self.task.enforce_timeout
        options["clock"] = self.task.clock

        if not self.task.timeout or self.task.timeout == 0:
            options["timeout"] = self.cfg.timeouts.default
        else:
            options["timeout"] = self.task.timeout

        if self.task.category == "file":
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()

        return options

    def launch_analysis(self):
        """Start analysis."""
        succeeded = False
        dead_machine = False

        log.info("Starting analysis of %s \"%s\" (task=%d)",
                 self.task.category.upper(), self.task.target, self.task.id)

        # Initialize the the analysis folders.
        if not self.init_storage():
            return False

        if self.task.category == "file":
            # Check whether the file has been changed for some unknown reason.
            # And fail this analysis if it has been modified.
            if not self.check_file():
                return False

            # Store a copy of the original file.
            if not self.store_file():
                return False

        # Acquire analysis machine.
        try:
            self.acquire_machine()
        except CuckooOperationalError as e:
            log.error("Cannot acquire machine: {0}".format(e))
            return False

        # Generate the analysis configuration file.
        options = self.build_options()

        # At this point we can tell the Resultserver about it.
        try:
            Resultserver().add_task(self.task, self.machine)
        except Exception as e:
            machinery.release(self.machine.label)
            self.errors.put(e)

        aux = RunAuxiliary(task=self.task, machine=self.machine)
        aux.start()

        try:
            # Mark the selected analysis machine in the database as started.
            guest_log = Database().guest_start(self.task.id,
                                               self.machine.name,
                                               self.machine.label,
                                               machinery.__class__.__name__)
            # Start the machine.
            machinery.start(self.machine.label)
        except CuckooMachineError as e:
            log.error(str(e), extra={"task_id": self.task.id})
            dead_machine = True
        else:
            try:
                # Initialize the guest manager.
                guest = GuestManager(self.machine.name, self.machine.ip, self.machine.platform)
                # Start the analysis.
                guest.start_analysis(options)
            except CuckooGuestError as e:
                log.error(str(e), extra={"task_id": self.task.id})
            else:
                # Wait for analysis completion.
                try:
                    guest.wait_for_completion()
                    succeeded = True
                except CuckooGuestError as e:
                    log.error(str(e), extra={"task_id": self.task.id})
                    succeeded = False

        finally:
            # Stop Auxiliary modules.
            aux.stop()

            # Take a memory dump of the machine before shutting it off.
            if self.cfg.cuckoo.memory_dump or self.task.memory:
                try:
                    machinery.dump_memory(self.machine.label,
                                          os.path.join(self.storage, "memory.dmp"))
                except NotImplementedError:
                    log.error("The memory dump functionality is not available "
                              "for the current machine manager")
                except CuckooMachineError as e:
                    log.error(e)

            try:
                # Stop the analysis machine.
                machinery.stop(self.machine.label)
            except CuckooMachineError as e:
                log.warning("Unable to stop machine %s: %s",
                            self.machine.label, e)

            # Mark the machine in the database as stopped. Unless this machine
            # has been marked as dead, we just keep it as "started" in the
            # database so it'll not be used later on in this session.
            Database().guest_stop(guest_log)

            # After all this, we can make the Resultserver forget about the
            # internal state for this analysis task.
            Resultserver().del_task(self.task, self.machine)

            if dead_machine:
                # Remove the guest from the database, so that we can assign a
                # new guest when the task is being analyzed with another
                # machine.
                Database().guest_remove(guest_log)

                # Remove the analysis directory that has been created so
                # far, as launch_analysis() is going to be doing that again.
                shutil.rmtree(self.storage)

                # This machine has turned dead, so we throw an exception here
                # which informs the AnalysisManager that it should analyze
                # this task again with another available machine.
                raise CuckooDeadMachine()

            try:
                # Release the analysis machine. But only if the machine has
                # not turned dead yet.
                machinery.release(self.machine.label)
            except CuckooMachineError as e:
                log.error("Unable to release machine %s, reason %s. "
                          "You might need to restore it manually",
                          self.machine.label, e)

        return succeeded

    def process_results(self):
        """Process the analysis results and generate the enabled reports."""
        results = RunProcessing(task_id=self.task.id).run()
        RunSignatures(results=results).run()
        RunReporting(task_id=self.task.id, results=results).run()

        # If the target is a file and the user enabled the option,
        # delete the original copy.
        if self.task.category == "file" and self.cfg.cuckoo.delete_original:
            if not os.path.exists(self.task.target):
                log.warning("Original file does not exist anymore: \"%s\": "
                            "File not found", self.task.target)
            else:
                try:
                    os.remove(self.task.target)
                except OSError as e:
                    log.error("Unable to delete original file at path "
                              "\"%s\": %s", self.task.target, e)

        # If the target is a file and the user enabled the delete copy of
        # the binary option, then delete the copy.
        if self.task.category == "file" and self.cfg.cuckoo.delete_bin_copy:
            if not os.path.exists(self.binary):
                log.warning("Copy of the original file does not exist anymore: \"%s\": File not found", self.binary)
            else:
                try:
                    os.remove(self.binary)
                except OSError as e:
                    log.error("Unable to delete the copy of the original file at path \"%s\": %s", self.binary, e)

        log.info("Task #%d: reports generation completed (path=%s)",
                 self.task.id, self.storage)

        return True

    def run(self):
        """Run manager thread."""
        global active_analysis_count
        active_analysis_count += 1
        try:
            while True:
                try:
                    success = self.launch_analysis()
                except CuckooDeadMachine:
                    continue

                break

            Database().set_status(self.task.id, TASK_COMPLETED)

            log.debug("Released database task #%d with status %s",
                      self.task.id, success)

            if self.cfg.cuckoo.process_results:
                self.process_results()
                Database().set_status(self.task.id, TASK_REPORTED)

            log.info("Task #%d: analysis procedure completed", self.task.id)
        except:
            log.exception("Failure in AnalysisManager.run")

        active_analysis_count -= 1

class Scheduler:
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """

    def __init__(self):
        self.running = True
        self.cfg = Config()
        self.db = Database()

    def initialize(self):
        """Initialize the machine manager."""
        global machinery

        machinery_name = self.cfg.cuckoo.machinery

        log.info("Using \"%s\" machine manager", machinery_name)

        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinery")[0]
        # Initialize the machine manager.
        machinery = plugin()

        # Find its configuration file.
        conf = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery_name)

        if not os.path.exists(conf):
            raise CuckooCriticalError("The configuration file for machine "
                                      "manager \"{0}\" does not exist at path:"
                                      " {1}".format(machinery_name, conf))

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        machinery.set_options(Config(conf))
        # Initialize the machine manager.
        try:
            machinery.initialize(machinery_name)
        except CuckooMachineError as e:
            raise CuckooCriticalError("Error initializing machines: %s" % e)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if len(machinery.machines()) == 0:
            raise CuckooCriticalError("No machines available")
        else:
            log.info("Loaded %s machine/s", len(machinery.machines()))

    def stop(self):
        """Stop scheduler."""
        self.running = False
        # Shutdown machine manager (used to kill machines that still alive).
        machinery.shutdown()

    def start(self):
        """Start scheduler."""
        global total_analysis_count
        self.initialize()

        log.info("Waiting for analysis tasks...")

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = Queue.Queue()

        maxcount = self.cfg.cuckoo.max_analysis_count

        # This loop runs forever.
        while self.running:
            time.sleep(1)

            # If not enough free diskspace is available, then we print an
            # error message and wait another round (this check is ignored
            # when freespace is set to zero).
            if self.cfg.cuckoo.freespace:
                # Resolve the full base path to the analysis folder, just in
                # case somebody decides to make a symlink out of it.
                dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")

                # TODO: Windows support
                if hasattr(os, "statvfs"):
                    dir_stats = os.statvfs(dir_path)

                    # Free diskspace in megabytes.
                    space_available = dir_stats.f_bavail * dir_stats.f_frsize
                    space_available /= 1024 * 1024

                    if space_available < self.cfg.cuckoo.freespace:
                        log.error("Not enough free diskspace! (Only %d MB!)",
                                  space_available)
                        continue

            # If no machines are available, it's pointless to fetch for
            # pending tasks. Loop over.
            if machinery.availables() == 0:
                continue

            # Exits if max_analysis_count is defined in config file and
            # is reached.
            if maxcount and total_analysis_count >= maxcount:
                if active_analysis_count <= 0:
                    self.stop()
            else:
                # Fetch a pending analysis task.
                task = self.db.fetch()

                if task:
                    log.debug("Processing task #%s", task.id)
                    total_analysis_count += 1

                    # Initialize the analysis manager.
                    analysis = AnalysisManager(task, errors)
                    # Start.
                    analysis.start()

            # Deal with errors.
            try:
                error = errors.get(block=False)
            except Queue.Empty:
                pass
            else:
                raise error
