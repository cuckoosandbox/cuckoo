# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import shutil
import logging
from threading import Thread, Lock

from lib.cuckoo.common.exceptions import CuckooAnalysisError, CuckooMachineError, CuckooGuestError, CuckooOperationalError
from lib.cuckoo.common.abstracts import  MachineManager
from lib.cuckoo.common.objects import Dictionary, File
from lib.cuckoo.common.utils import  create_folders, create_folder
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.sniffer import Sniffer
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)

mmanager = None
machine_lock = Lock()

class AnalysisManager(Thread):
    """Analysis manager thread."""

    def __init__(self, task):
        """@param task: task."""
        Thread.__init__(self)
        Thread.daemon = True

        # Object pointing to the current task assigned to this analysis
        # instance.
        self.task = task
        # Cuckoo configuration.
        self.cfg = Config()
        # Path to the analysis results folder assigned to this task.
        self.storage = ""
        # Path to a copy of the original binary file, if available.
        self.binary = ""

    def init_storage(self):
        """Initialize analysis storage folder.
        @raise CuckooAnalysisError: if storage folder already exists.
        """
        self.storage = os.path.join(CUCKOO_ROOT,
                                    "storage",
                                    "analyses",
                                    str(self.task.id))

        if os.path.exists(self.storage):
            raise CuckooAnalysisError("Analysis results folder already exists at path \"%s\", analysis aborted" % self.storage)

        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            raise CuckooAnalysisError("Unable to create analysis folder %s" % self.storage)

    def store_file(self):
        """Store sample file.
        @raise CuckooAnalysisError: if unable to store a copy of the file.
        """
        md5 = File(self.task.target).get_md5()
        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", md5)

        if os.path.exists(self.binary):
            log.info("File already exists at \"%s\"" % self.binary)
        else:
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error) as e:
                raise CuckooAnalysisError("Unable to store file from \"%s\" to \"%s\", analysis aborted" % (self.task.target, self.binary))

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            # On Windows systems, symlink is obviously not supported, therefore we'll just copy
            # the binary until we find a more efficient solution.
            if hasattr(os, "symlink"):
                os.symlink(self.binary, new_binary_path)
            else:
                shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            raise CuckooAnalysisError("Unable to create symlink/copy from \"%s\" to \"%s\"" % (self.binary, self.storage))

    def build_options(self):
        """Get analysis options.
        @return: options dict.
        """
        options = {}

        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["machine"] = self.task.machine
        options["platform"] = self.task.platform
        options["options"] = self.task.options
        options["custom"] = self.task.custom
        options["started"] = time.time()

        if not self.task.timeout or self.task.timeout == 0:
            options["timeout"] = self.cfg.cuckoo.analysis_timeout
        else:
            options["timeout"] = self.task.timeout

        if self.task.category == "file":
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()

        return options

    def launch_analysis(self):
        """Start analysis.
        @raise CuckooAnalysisError: if unable to start analysis.
        """
        log.info("Starting analysis of %s \"%s\" (task=%d)" % (self.task.category.upper(), self.task.target, self.task.id))

        # Initialize the the analysis folders.
        self.init_storage()

        # Check if the submitted target is a file, and if it is, check if it
        # actually does exist, otherwise abort the analysis.
        if self.task.category == "file":
            if not os.path.exists(self.task.target):
                raise CuckooAnalysisError("The file to analyze does not exist at path \"%s\", analysis aborted" % self.task.target)
            
            # Store a copy of the original file.
            self.store_file()

        # Generate the analysis configuration file.
        options = self.build_options()

        # Start a loop to acquire the a machine to run the analysis on.
        while True:
            machine_lock.acquire()
            # If the user specified a specific machine ID or a platform to be
            # used, acquire the machine accordingly.
            vm = mmanager.acquire(machine_id=self.task.machine,
                                  platform=self.task.platform)
            machine_lock.release()

            # If no machine is available at this moment, wait for one second and try again.
            if not vm:
                log.debug("Task #%d: no machine available yet" % self.task.id)
                time.sleep(1)
            else:
                log.info("Task #%d: acquired machine %s (label=%s)" % (self.task.id, vm.id, vm.label))
                break

        # If enabled in the configuration, start the tcpdump instance.
        if self.cfg.cuckoo.use_sniffer:
            sniffer = Sniffer(self.cfg.cuckoo.tcpdump)
            sniffer.start(interface=self.cfg.cuckoo.interface,
                          host=vm.ip,
                          file_path=os.path.join(self.storage, "dump.pcap"))
        else:
            sniffer = False

        try:
            # Start machine.
            guest_log = Database().guest_start(self.task.id,
                                               vm.id,
                                               vm.label,
                                               mmanager.__class__.__name__)
            mmanager.start(vm.label)
            # Initialize guest manager.
            guest = GuestManager(vm.id, vm.ip, vm.platform)
            # Launch analysis.
            guest.start_analysis(options)
            # Wait for analysis to complete.
            success = guest.wait_for_completion()
            # Stop sniffer.
            if sniffer:
                sniffer.stop()

            # Save results.
            guest.save_results(self.storage)

            if not success:
                raise CuckooAnalysisError("Task #%d: analysis failed, review previous errors" % self.task.id)
        except (CuckooMachineError, CuckooGuestError) as e:
            raise CuckooAnalysisError(e)
        finally:
            # If the target is a file and the user enabled the option,
            # delete the original copy.
            if self.task.category == "file" and self.cfg.cuckoo.delete_original:
                try:
                    os.remove(self.task.target)
                except OSError as e:
                    log.error("Unable to delete original file at path \"%s\": %s" % (self.task.target, e))

            try:
                # Stop machine and log.
                mmanager.stop(vm.label)
                Database().guest_stop(guest_log)

                # Release the machine from lock.
                log.debug("Task #%d: releasing machine %s (label=%s)" % (self.task.id, vm.id, vm.label))
                mmanager.release(vm.label)
            except CuckooMachineError as e:
                log.error("Unable to release machine %s, reason %s. You might need to restore it manually" % (vm.label, e))

        # Check analysis file size to avoid memory leaks.
        try:
            logs_path = os.path.join(self.storage, "logs")
            for csv in os.listdir(logs_path):
                csv = os.path.join(logs_path, csv)
                if os.stat(csv).st_size > self.cfg.cuckoo.analysis_size_limit:
                    raise CuckooAnalysisError("Analysis file %s is too big to be processed, analysis aborted. Process it manually with the provided utilities" % csv)
        except OSError as e:
            log.warning("Log access error for analysis #%d: %s" % (self.task.id, e))

        # Launch reports generation.
        results = Processor(self.storage).run()
        Reporter(self.storage).run(results)

        log.info("Task #%d: reports generation completed (path=%s)" % (self.task.id, self.storage))

    def run(self):
        """Run manager thread."""
        success = True

        try:
            self.launch_analysis()
        except CuckooMachineError as e:
            log.error("Please check virtual machine status: %s" % e)
            success = False
        except CuckooAnalysisError as e:
            log.error(e)
            success = False
        finally:
            log.debug("Releasing database task #%d with status %s" % (self.task.id, success))
            Database().complete(self.task.id, success)

class Scheduler:
    """Task scheduler."""

    def __init__(self):
        self.running = True
        self.cfg = Config()
        self.db = Database()

    def initialize(self):
        """Initialize machine manager."""
        global mmanager

        log.info("Using \"%s\" machine manager" % self.cfg.cuckoo.machine_manager)
        name = "modules.machinemanagers.%s" % self.cfg.cuckoo.machine_manager

        # Import the machine manager specified in the configuration file.
        try:
            __import__(name, globals(), locals(), ["dummy"], -1)
        except ImportError as e:
            raise CuckooMachineError("Unable to import machine manager plugin: %s" % e)

        # Initialize the parent class.
        MachineManager()
        # Select the first subclass of the parent MachineManager. This is
        # the trick we use for implementing our plugins and identify them.
        module = MachineManager.__subclasses__()[0]
        # Initialize the machine manager.
        mmanager = module()
        # Find its configuration file.
        conf = os.path.join(CUCKOO_ROOT,
                            "conf",
                            "%s.conf" % self.cfg.cuckoo.machine_manager)

        if not os.path.exists(conf):
            raise CuckooMachineError("The configuration file for machine manager \"%s\" does not exist at path: %s"
                                     % (self.cfg.cuckoo.machine_manager, conf))

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        mmanager.set_options(Config(conf))
        # Initialize the machine manager.
        mmanager.initialize(self.cfg.cuckoo.machine_manager)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if len(mmanager.machines) == 0:
            raise CuckooMachineError("No machines available")
        else:
            log.info("Loaded %s machine/s" % len(mmanager.machines))

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

