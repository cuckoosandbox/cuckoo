# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import shutil
import logging
import threading
import Queue

from lib.cuckoo.common.config import Config, emit_options
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.log import task_log_start, task_log_stop
from lib.cuckoo.core.plugins import list_plugins, RunAuxiliary, RunProcessing
from lib.cuckoo.core.plugins import RunSignatures, RunReporting
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.rooter import rooter, vpns

log = logging.getLogger(__name__)

machinery = None
machine_lock = None
latest_symlink_lock = threading.Lock()

active_analysis_count = 0

class AnalysisManager(threading.Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(self, task_id, error_queue):
        """@param task: task object containing the details for the analysis."""
        threading.Thread.__init__(self)

        self.errors = error_queue
        self.cfg = Config()
        self.storage = ""
        self.binary = ""
        self.storage_binary = ""
        self.machine = None

        self.db = Database()
        self.task = self.db.view_task(task_id)
        self.guest_manager = None

        self.interface = None
        self.rt_table = None

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

    def check_permissions(self):
        """Checks if we have permissions to access the file to be analyzed."""
        if os.access(self.task.target, os.R_OK):
            return True

        log.error(
            "Unable to access target file, please check if we have "
            "permissions to access the file: \"%s\"",
            self.task.target
        )
        return False

    def check_file(self):
        """Checks the integrity of the file to be analyzed."""
        sample = self.db.view_sample(self.task.sample_id)

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
            self.storage_binary = os.path.join(self.storage, "binary")

            if hasattr(os, "symlink"):
                os.symlink(self.binary, self.storage_binary)
            else:
                shutil.copy(self.binary, self.storage_binary)
        except (AttributeError, OSError) as e:
            log.error("Unable to create symlink/copy from \"%s\" to "
                      "\"%s\": %s", self.binary, self.storage, e)

        return True

    def store_task_info(self):
        """grab latest task from db (if available) and update self.task"""
        dbtask = self.db.view_task(self.task.id)
        self.task = dbtask.to_dict()

        task_info_path = os.path.join(self.storage, "task.json")
        open(task_info_path, "w").write(dbtask.to_json())

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
            machine = machinery.acquire(machine_id=self.task.machine,
                                        platform=self.task.platform,
                                        tags=self.task.tags)

            # If no machine is available at this moment, wait for one second
            # and try again.
            if not machine:
                machine_lock.release()
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

        if self.task.category == "file":
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()
            options["pe_exports"] = \
                ",".join(File(self.task.target).get_exported_functions())

            package, activity = File(self.task.target).get_apk_entry()
            self.task.options["apk_entry"] = "%s:%s" % (package, activity)

        options["id"] = self.task.id
        options["ip"] = self.machine.resultserver_ip
        options["port"] = self.machine.resultserver_port
        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["options"] = emit_options(self.task.options)
        options["enforce_timeout"] = self.task.enforce_timeout
        options["clock"] = self.task.clock
        options["terminate_processes"] = self.cfg.cuckoo.terminate_processes

        if not self.task.timeout:
            options["timeout"] = self.cfg.timeouts.default
        else:
            options["timeout"] = self.task.timeout

        # copy in other analyzer specific options, TEMPORARY (most likely)
        vm_options = getattr(machinery.options, self.machine.name)
        for k in vm_options:
            if k.startswith("analyzer_"):
                options[k] = vm_options[k]

        return options

    def route_network(self):
        """Enable network routing if desired."""
        # Determine the desired routing strategy (none, internet, VPN).
        route = self.task.options.get("route", self.cfg.routing.route)

        if route == "none":
            self.interface = None
            self.rt_table = None
        elif route == "internet" and self.cfg.routing.internet != "none":
            self.interface = self.cfg.routing.internet
            self.rt_table = self.cfg.routing.rt_table
        elif route in vpns:
            self.interface = vpns[route].interface
            self.rt_table = vpns[route].rt_table
        else:
            log.warning("Unknown network routing destination specified, "
                        "ignoring routing for this analysis: %r", route)
            self.interface = None
            self.rt_table = None

        # Check if the network interface is still available. If a VPN dies for
        # some reason, its tunX interface will no longer be available.
        if self.interface and not rooter("nic_available", self.interface):
            log.error(
                "The network interface '%s' configured for this analysis is "
                "not available at the moment, switching to route=none mode.",
                self.interface
            )
            route = "none"
            self.task.options["route"] = "none"
            self.interface = None
            self.rt_table = None

        if self.interface:
            rooter("forward_enable", self.machine.interface,
                   self.interface, self.machine.ip)

        if self.rt_table:
            rooter("srcroute_enable", self.rt_table, self.machine.ip)

        # Propagate the taken route to the database.
        self.db.set_route(self.task.id, route)

    def unroute_network(self):
        if self.interface:
            rooter("forward_disable", self.machine.interface,
                   self.interface, self.machine.ip)

        if self.rt_table:
            rooter("srcroute_disable", self.rt_table, self.machine.ip)

    def wait_finish(self):
        """Some VMs don't have an actual agent. Mainly those that are used as
        assistance for an analysis through the services auxiliary module. This
        method just waits until the analysis is finished rather than actively
        trying to engage with the Cuckoo Agent."""
        self.db.guest_set_status(self.task.id, "running")
        while self.db.guest_get_status(self.task.id) == "running":
            time.sleep(1)

    def guest_manage(self, options):
        # Handle a special case where we're creating a baseline report of this
        # particular virtual machine - a report containing all the results
        # that are gathered if no additional samples are ran in the VM. These
        # results, such as loaded drivers and opened sockets in volatility, or
        # DNS requests to hostnames related to Microsoft Windows, etc may be
        # omitted or at the very least given less priority when creating a
        # report for an analysis that ran on this VM later on.
        if self.task.category == "baseline":
            time.sleep(options["timeout"])
        else:
            # Start the analysis.
            self.db.guest_set_status(self.task.id, "starting")
            monitor = self.task.options.get("monitor", "latest")
            self.guest_manager.start_analysis(options, monitor)

            # In case the Agent didn't respond and we force-quit the analysis
            # at some point while it was still starting the analysis the state
            # will be "stop" (or anything but "running", really).
            if self.db.guest_get_status(self.task.id) == "starting":
                self.db.guest_set_status(self.task.id, "running")
                self.guest_manager.wait_for_completion()

            self.db.guest_set_status(self.task.id, "stopping")

    def launch_analysis(self):
        """Start analysis."""
        succeeded = False

        target = self.task.target
        if self.task.category == "file":
            target = os.path.basename(target)

        log.info("Starting analysis of %s \"%s\" (task #%d, options \"%s\")",
                 self.task.category.upper(), target, self.task.id,
                 emit_options(self.task.options))

        # Initialize the analysis folders.
        if not self.init_storage():
            return False

        # Initiates per-task logging.
        task_log_start(self.task.id)

        self.store_task_info()

        if self.task.category == "file":
            # Check if we have permissions to access the file.
            # And fail this analysis if we don't have access to the file.
            if not self.check_permissions():
                return False

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
            machine_lock.release()
            log.error("Cannot acquire machine: {0}".format(e))
            return False

        # At this point we can tell the ResultServer about it.
        try:
            ResultServer().add_task(self.task, self.machine)
        except Exception as e:
            machinery.release(self.machine.label)
            self.errors.put(e)

        # Initialize the guest manager.
        self.guest_manager = GuestManager(
            self.machine.name, self.machine.ip,
            self.machine.platform, self.task.id, self
        )

        self.aux = RunAuxiliary(self.task, self.machine, self.guest_manager)
        self.aux.start()

        # Generate the analysis configuration file.
        options = self.build_options()

        try:
            unlocked = False
            self.interface = None

            # Mark the selected analysis machine in the database as started.
            guest_log = self.db.guest_start(self.task.id,
                                            self.machine.name,
                                            self.machine.label,
                                            machinery.__class__.__name__)
            # Start the machine.
            machinery.start(self.machine.label, self.task)

            # Enable network routing.
            self.route_network()

            # By the time start returns it will have fully started the Virtual
            # Machine. We can now safely release the machine lock.
            machine_lock.release()
            unlocked = True

            # Run and manage the components inside the guest unless this
            # machine has the "noagent" option specified (please refer to the
            # wait_finish() function for more details on this function).
            if "noagent" not in self.machine.options:
                self.guest_manage(options)
            else:
                self.wait_finish()

            succeeded = True
        except CuckooMachineError as e:
            if not unlocked:
                machine_lock.release()
            log.error(
                "Machinery error: %s",
                e, extra={"task_id": self.task.id}
            )
            log.critical(
                "A critical error has occurred trying to use the machine "
                "with name %s during an analysis due to which it is no "
                "longer in a working state, please report this issue and all "
                "of the related environment details to the developers so we "
                "can improve this situation. (Note that before we would "
                "simply remove this VM from doing any more analyses, but as "
                "all the VMs will eventually be depleted that way, hopefully "
                "we'll find a better solution now).", self.machine.name,
            )
        except CuckooGuestError as e:
            if not unlocked:
                machine_lock.release()
            log.error(
                "Error from the Cuckoo Guest: %s",
                e, extra={"task_id": self.task.id}
            )
        finally:
            # Stop Auxiliary modules.
            self.aux.stop()

            # Take a memory dump of the machine before shutting it off.
            if self.cfg.cuckoo.memory_dump or self.task.memory:
                try:
                    dump_path = os.path.join(self.storage, "memory.dmp")
                    machinery.dump_memory(self.machine.label, dump_path)
                except NotImplementedError:
                    log.error("The memory dump functionality is not available "
                              "for the current machine manager.")
                except CuckooMachineError as e:
                    log.error("Machinery error: %s", e)

            try:
                # Stop the analysis machine.
                machinery.stop(self.machine.label)
            except CuckooMachineError as e:
                log.warning("Unable to stop machine %s: %s",
                            self.machine.label, e)

            # Mark the machine in the database as stopped. Unless this machine
            # has been marked as dead, we just keep it as "started" in the
            # database so it'll not be used later on in this session.
            self.db.guest_stop(guest_log)

            # After all this, we can make the ResultServer forget about the
            # internal state for this analysis task.
            ResultServer().del_task(self.task, self.machine)

            # Drop the network routing rules if any.
            self.unroute_network()

            try:
                # Release the analysis machine. But only if the machine has
                # not turned dead yet.
                machinery.release(self.machine.label)
            except CuckooMachineError as e:
                log.error("Unable to release machine %s, reason %s. "
                          "You might need to restore it manually.",
                          self.machine.label, e)

        return succeeded

    def process_results(self):
        """Process the analysis results and generate the enabled reports."""
        results = RunProcessing(task=self.task).run()
        RunSignatures(results=results).run()
        RunReporting(task=self.task, results=results).run()

        # If the target is a file and the user enabled the option,
        # delete the original copy.
        if self.task.category == "file" and self.cfg.cuckoo.delete_original:
            if not os.path.exists(self.task.target):
                log.warning("Original file does not exist anymore: \"%s\": "
                            "File not found.", self.task.target)
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
            # Check if the binary in the analysis directory is an invalid symlink. If it is, delete it.
            if os.path.islink(self.storage_binary) and not os.path.exists(self.storage_binary):
                try:
                    os.remove(self.storage_binary)
                except OSError as e:
                    log.error("Unable to delete symlink to the binary copy at path \"%s\": %s", self.storage_binary, e)

        log.info("Task #%d: reports generation completed (path=%s)",
                 self.task.id, self.storage)

        return True

    def run(self):
        """Run manager thread."""
        global active_analysis_count
        active_analysis_count += 1
        try:
            self.launch_analysis()

            self.db.set_status(self.task.id, TASK_COMPLETED)

            log.debug("Released database task #%d", self.task.id)

            if self.cfg.cuckoo.process_results:
                # this updates self.task so processing gets the latest and greatest
                self.store_task_info()

                self.process_results()
                self.db.set_status(self.task.id, TASK_REPORTED)

            # We make a symbolic link ("latest") which links to the latest
            # analysis - this is useful for debugging purposes. This is only
            # supported under systems that support symbolic links.
            if hasattr(os, "symlink"):
                latest = os.path.join(CUCKOO_ROOT, "storage",
                                      "analyses", "latest")

                # First we have to remove the existing symbolic link, then we
                # have to create the new one.
                # Deal with race conditions using a lock.
                latest_symlink_lock.acquire()
                try:
                    # As per documentation, lexists() returns True for dead
                    # symbolic links.
                    if os.path.lexists(latest):
                        os.remove(latest)

                    os.symlink(self.storage, latest)
                except OSError as e:
                    log.warning("Error pointing latest analysis symlink: %s" % e)
                finally:
                    latest_symlink_lock.release()

            # overwrite task.json so we have the latest data inside
            self.store_task_info()
            log.info("Task #%d: analysis procedure completed", self.task.id)
        except:
            log.exception("Failure in AnalysisManager.run")

        task_log_stop(self.task.id)
        active_analysis_count -= 1

class Scheduler(object):
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """
    def __init__(self, maxcount=None):
        self.running = True
        self.cfg = Config()
        self.db = Database()
        self.maxcount = maxcount
        self.total_analysis_count = 0

    def initialize(self):
        """Initialize the machine manager."""
        global machinery, machine_lock

        machinery_name = self.cfg.cuckoo.machinery

        max_vmstartup_count = self.cfg.cuckoo.max_vmstartup_count
        if max_vmstartup_count:
            machine_lock = threading.Semaphore(max_vmstartup_count)
        else:
            machine_lock = threading.Lock()

        log.info("Using \"%s\" as machine manager", machinery_name)

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
        machinery.set_options(Config(machinery_name))

        # Initialize the machine manager.
        try:
            machinery.initialize(machinery_name)
        except CuckooMachineError as e:
            raise CuckooCriticalError("Error initializing machines: %s" % e)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if not len(machinery.machines()):
            raise CuckooCriticalError("No machines available.")
        else:
            log.info("Loaded %s machine/s", len(machinery.machines()))

        if len(machinery.machines()) > 1 and self.db.engine.name == "sqlite":
            log.warning("As you've configured Cuckoo to execute parallel "
                        "analyses, we recommend you to switch to a MySQL or"
                        "a PostgreSQL database as SQLite might cause some "
                        "issues.")

        if len(machinery.machines()) > 4 and self.cfg.cuckoo.process_results:
            log.warning("When running many virtual machines it is recommended "
                        "to process the results in a separate process.py to "
                        "increase throughput and stability. Please read the "
                        "documentation about the `Processing Utility`.")

        # Drop all existing packet forwarding rules for each VM. Just in case
        # Cuckoo was terminated for some reason and various forwarding rules
        # have thus not been dropped yet.
        for machine in machinery.machines():
            if not machine.interface:
                log.info("Unable to determine the network interface for VM "
                         "with name %s, Cuckoo will not be able to give it "
                         "full internet access or route it through a VPN! "
                         "Please define a default network interface for the "
                         "machinery or define a network interface for each "
                         "VM.", machine.name)
                continue

            # Drop forwarding rule to each VPN.
            for vpn in vpns.values():
                rooter("forward_disable", machine.interface,
                       vpn.interface, machine.ip)

            # Drop forwarding rule to the internet / dirty line.
            if self.cfg.routing.internet != "none":
                rooter("forward_disable", machine.interface,
                       self.cfg.routing.internet, machine.ip)

    def stop(self):
        """Stop scheduler."""
        self.running = False
        # Shutdown machine manager (used to kill machines that still alive).
        machinery.shutdown()

    def start(self):
        """Start scheduler."""
        self.initialize()

        log.info("Waiting for analysis tasks.")

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = Queue.Queue()

        # Command-line overrides the configuration file.
        if self.maxcount is None:
            self.maxcount = self.cfg.cuckoo.max_analysis_count

        # This loop runs forever.
        while self.running:
            time.sleep(1)

            # Wait until the machine lock is not locked. This is only the case
            # when all machines are fully running, rather that about to start
            # or still busy starting. This way we won't have race conditions
            # with finding out there are no available machines in the analysis
            # manager or having two analyses pick the same machine.
            if not machine_lock.acquire(False):
                continue

            machine_lock.release()

            # If not enough free disk space is available, then we print an
            # error message and wait another round (this check is ignored
            # when the freespace configuration variable is set to zero).
            if self.cfg.cuckoo.freespace:
                # Resolve the full base path to the analysis folder, just in
                # case somebody decides to make a symbolic link out of it.
                dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")

                # TODO: Windows support
                if hasattr(os, "statvfs"):
                    dir_stats = os.statvfs(dir_path)

                    # Calculate the free disk space in megabytes.
                    space_available = dir_stats.f_bavail * dir_stats.f_frsize
                    space_available /= 1024 * 1024

                    if space_available < self.cfg.cuckoo.freespace:
                        log.error("Not enough free disk space! (Only %d MB!)",
                                  space_available)
                        continue

            # Have we limited the number of concurrently executing machines?
            if self.cfg.cuckoo.max_machines_count:
                # Are too many running?
                if len(machinery.running()) >= self.cfg.cuckoo.max_machines_count:
                    continue

            # If no machines are available, it's pointless to fetch for
            # pending tasks. Loop over.
            if not machinery.availables():
                continue

            # Exits if max_analysis_count is defined in the configuration
            # file and has been reached.
            if self.maxcount and self.total_analysis_count >= self.maxcount:
                if active_analysis_count <= 0:
                    log.debug("Reached max analysis count, exiting.")
                    self.stop()
                continue

            # Fetch a pending analysis task.
            # TODO This fixes only submissions by --machine, need to add
            # other attributes (tags etc).
            # TODO We should probably move the entire "acquire machine" logic
            # from the Analysis Manager to the Scheduler and then pass the
            # selected machine onto the Analysis Manager instance.
            task, available = None, False
            for machine in self.db.get_available_machines():
                task = self.db.fetch(machine=machine.name)
                if task:
                    break

                if machine.is_analysis():
                    available = True

            # We only fetch a new task if at least one of the available
            # machines is not a "service" machine (again, please refer to the
            # services auxiliary module for more information on service VMs).
            if not task and available:
                task = self.db.fetch(service=False)

            if task:
                log.debug("Processing task #%s", task.id)
                self.total_analysis_count += 1

                # Initialize and start the analysis manager.
                analysis = AnalysisManager(task.id, errors)
                analysis.daemon = True
                analysis.start()

            # Deal with errors.
            try:
                raise errors.get(block=False)
            except Queue.Empty:
                pass

        log.debug("End of analyses.")
