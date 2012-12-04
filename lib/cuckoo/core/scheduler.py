# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import shutil
import logging
from threading import Thread, Lock

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.exceptions import CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.abstracts import  MachineManager
from lib.cuckoo.common.objects import Dictionary, File
from lib.cuckoo.common.utils import  create_folders, create_folder
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.sniffer import Sniffer
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter
from lib.cuckoo.core.plugins import import_plugin, list_plugins

log = logging.getLogger(__name__)

mmanager = None
machine_lock = Lock()

class AnalysisManager(Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(self, task):
        """@param task: task object containing the details for the analysis."""
        Thread.__init__(self)
        Thread.daemon = True

        self.task = task
        self.cfg = Config()
        self.storage = ""
        self.binary = ""

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
                      " analysis aborted" % self.storage)
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            log.error("Unable to create analysis folder %s" % self.storage)
            return False

        return True

    def store_file(self):
        """Store a copy of the file being analyzed."""
        if not os.path.exists(self.task.target):
            log.error("The file to analyze does not exist at path \"%s\", "
                      "analysis aborted" % self.task.target)
            return False

        sha256 = File(self.task.target).get_sha256()
        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)

        if os.path.exists(self.binary):
            log.info("File already exists at \"%s\"" % self.binary)
        else:
            # TODO: do we really need to abort the analysis in case we are not
            # able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error) as e:
                log.error("Unable to store file from \"%s\" to \"%s\", "
                          "analysis aborted" % (self.task.target, self.binary))
                return False

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            if hasattr(os, "symlink"):
                os.symlink(self.binary, new_binary_path)
            else:
                shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            log.error("Unable to create symlink/copy from \"%s\" to \"%s\""
                      % (self.binary, self.storage))

        return True

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None

        # Start a loop to acquire the a machine to run the analysis on.
        while True:
            machine_lock.acquire()
            # If the user specified a specific machine ID or a platform to be
            # used, acquire the machine accordingly.
            machine = mmanager.acquire(machine_id=self.task.machine,
                                       platform=self.task.platform)
            machine_lock.release()

            # If no machine is available at this moment, wait for one second
            # and try again.
            if not machine:
                log.debug("Task #%d: no machine available yet" % self.task.id)
                time.sleep(1)
            else:
                log.info("Task #%d: acquired machine %s (label=%s)"
                         % (self.task.id, machine.name, machine.label))
                break

        return machine

    def build_options(self):
        """Generate analysis options.
        @return: options dict.
        """
        options = {}

        options["id"] = self.task.id
        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["machine"] = self.task.machine
        options["platform"] = self.task.platform
        options["options"] = self.task.options
        options["custom"] = self.task.custom
        options["enforce_timeout"] = self.task.enforce_timeout
        options["started"] = time.time()

        if not self.task.timeout or self.task.timeout == 0:
            options["timeout"] = self.cfg.timeouts.default
        else:
            options["timeout"] = self.task.timeout

        if self.task.category == "file":
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()

        return options

    def process_results(self):
        """Process the analysis results and generate the enabled reports."""
        try:
            logs_path = os.path.join(self.storage, "logs")
            for csv in os.listdir(logs_path):
                csv = os.path.join(logs_path, csv)
                if os.stat(csv).st_size > self.cfg.processing.analysis_size_limit:
                    log.error("Analysis file %s is too big to be processed, "
                              "analysis aborted. Process it manually with the "
                              "provided utilities" % csv)
                    return False
        except OSError as e:
            log.warning("Error accessing analysis logs (task=%d): %s"
                        % (self.task.id, e))

        results = Processor(self.storage).run()
        Reporter(self.storage).run(results)

        log.info("Task #%d: reports generation completed (path=%s)"
                 % (self.task.id, self.storage))

        return True

    def launch_analysis(self):
        """Start analysis."""
        sniffer = None
        succeeded = False
        stored = False

        log.info("Starting analysis of %s \"%s\" (task=%d)"
                 % (self.task.category.upper(),
                    self.task.target, self.task.id))

        # Initialize the the analysis folders.
        if not self.init_storage():
            return False

        if self.task.category == "file":
            # Store a copy of the original file.
            if not self.store_file():
                return False

        # Generate the analysis configuration file.
        options = self.build_options()

        # Acquire analysis machine.
        machine = self.acquire_machine()

        # If enabled in the configuration, start the tcpdump instance.
        if self.cfg.sniffer.enabled:
            sniffer = Sniffer(self.cfg.sniffer.tcpdump)
            sniffer.start(interface=self.cfg.sniffer.interface,
                          host=machine.ip,
                          file_path=os.path.join(self.storage, "dump.pcap"))

        try:
            # Mark the selected analysis machine in the database as started.
            guest_log = Database().guest_start(self.task.id,
                                               machine.name,
                                               machine.label,
                                               mmanager.__class__.__name__)
            # Start the machine.
            mmanager.start(machine.label)
        except CuckooMachineError as e:
            log.error(str(e), extra={"task_id" : self.task.id})

            # Stop the sniffer.
            if sniffer:
                sniffer.stop()

            return False
        else:
            try:
                # Initialize the guest manager.
                guest = GuestManager(machine.name, machine.ip, machine.platform)
                # Start the analysis.
                guest.start_analysis(options)
            except CuckooGuestError as e:
                log.error(str(e), extra={"task_id" : self.task.id})

                # Stop the sniffer.
                if sniffer:
                    sniffer.stop()

                return False
            else:
                # Wait for analysis completion.
                try:
                    guest.wait_for_completion()
                    succeeded = True
                except CuckooGuestError as e:
                    log.error(str(e), extra={"task_id" : self.task.id})
                    succeeded = False

                # Retrieve the analysis results and store them.
                try:
                    guest.save_results(self.storage)
                    stored = True
                except CuckooGuestError as e:
                    log.error(str(e), extra={"task_id" : self.task.id})
                    stored = False
        finally:
            # Stop the sniffer.
            if sniffer:
                sniffer.stop()

            # If the target is a file and the user enabled the option,
            # delete the original copy.
            if self.task.category == "file" and self.cfg.cuckoo.delete_original:
                try:
                    os.remove(self.task.target)
                except OSError as e:
                    log.error("Unable to delete original file at path \"%s\": "
                              "%s" % (self.task.target, e))

            # Take a memory dump of the machine before shutting it off.
            do_memory_dump = False
            if self.cfg.cuckoo.memory_dump:
                do_memory_dump = True
            else:
                if self.task.memory:
                    do_memory_dump = True

            if do_memory_dump:
                try:
                    mmanager.dump_memory(machine.label,
                                         os.path.join(self.storage, "memory.dmp"))
                except NotImplementedError:
                    log.error("The memory dump functionality is not available "
                              "for current machine manager")
                except CuckooMachineError as e:
                    log.error(e)

            try:
                # Stop the analysis machine.
                mmanager.stop(machine.label)
                # Market the machine in the database as stopped.
                Database().guest_stop(guest_log)
                # Release the analysis machine.
                mmanager.release(machine.label)
            except CuckooMachineError as e:
                log.error("Unable to release machine %s, reason %s. "
                          "You might need to restore it manually"
                          % (machine.label, e))

        # If the results were correctly stored, we process the results and
        # generate the reports.
        if stored:
            self.process_results()

        return succeeded

    def run(self):
        """Run manager thread."""
        success = self.launch_analysis()

        log.debug("Releasing database task #%d with status %s"
                  % (self.task.id, success))
        Database().complete(self.task.id, success)

        log.info("Task #%d: analysis procedure completed"
                 % self.task.id)

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
        global mmanager

        mmanager_name = self.cfg.cuckoo.machine_manager

        log.info("Using \"%s\" machine manager" % mmanager_name)

        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinemanagers")[0]
        # Initialize the machine manager.
        mmanager = plugin()

        # Find its configuration file.
        conf = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % mmanager_name)

        if not os.path.exists(conf):
            raise CuckooCriticalError("The configuration file for machine "
                                      "manager \"%s\" does not exist at path: "
                                      "%s" % (mmanager_name, conf))

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        mmanager.set_options(Config(conf))
        # Initialize the machine manager.
        mmanager.initialize(mmanager_name)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if mmanager.machines().count() == 0:
            raise CuckooCriticalError("No machines available")
        else:
            log.info("Loaded %s machine/s" % mmanager.machines().count())

    def stop(self):
        """Stop scheduler."""
        self.running = False
        # Shutdown machine manager (used to kill machines that still alive).
        mmanager.shutdown()

    def start(self):
        """Start scheduler."""
        self.initialize()

        log.info("Waiting for analysis tasks...")

        # This loop runs forever.
        while self.running:
            time.sleep(1)

            # If no machines are available, it's pointless to fetch for
            # pending tasks. Loop over.
            if mmanager.availables() == 0:
                continue

            # Fetch a pending analysis task.
            task = self.db.fetch_and_process()

            if task:
                log.debug("Processing task #%s" % task.id)

                # Initialize the analysis manager.
                analysis = AnalysisManager(task)
                analysis.daemon = True
                # Start.
                analysis.start()
