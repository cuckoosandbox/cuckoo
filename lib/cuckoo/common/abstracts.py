# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import logging
import time

import xml.etree.ElementTree as ET

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import Dictionary
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.database import Database

try:
    import libvirt
    HAVE_LIBVIRT = True
except ImportError:
    HAVE_LIBVIRT = False

log = logging.getLogger(__name__)

class Auxiliary(object):
    """Base abstract class for auxiliary modules."""

    def __init__(self):
        self.task = None
        self.machine = None
        self.guest_manager = None
        self.options = None

    def set_task(self, task):
        self.task = task

    def set_machine(self, machine):
        self.machine = machine

    def set_guest_manager(self, guest_manager):
        self.guest_manager = guest_manager

    def set_options(self, options):
        self.options = options

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

class Machinery(object):
    """Base abstract class for machinery modules."""

    # Default label used in machinery configuration file to supply virtual
    # machine name/label/vmx path. Override it if you dubbed it in another
    # way.
    LABEL = "label"

    def __init__(self):
        self.module_name = ""
        self.options = None
        self.options_globals = Config()
        # Database pointer.
        self.db = Database()

        # Machine table is cleaned to be filled from configuration file
        # at each start.
        self.db.clean_machines()

    def pcap_path(self, task_id):
        """Returns the .pcap path for this task id."""
        return os.path.join(CUCKOO_ROOT, "storage", "analyses",
                            "%s" % task_id, "dump.pcap")

    def set_options(self, options):
        """Set machine manager options.
        @param options: machine manager options dict.
        """
        self.options = options

    def initialize(self, module_name):
        """Read, load, and verify machines configuration.
        @param module_name: module name.
        """
        # Load.
        self._initialize(module_name)

        # Run initialization checks.
        self._initialize_check()

    def _get_resultserver_port(self):
        """Returns the ResultServer port."""
        # Avoid import recursion issues by importing ResultServer here.
        from lib.cuckoo.core.resultserver import ResultServer
        return ResultServer().port

    def _initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        self.module_name = module_name
        mmanager_opts = self.options.get(module_name)

        for machine_id in mmanager_opts["machines"].strip().split(","):
            try:
                machine_opts = self.options.get(machine_id.strip())
                machine = Dictionary()
                machine.id = machine_id.strip()
                machine.label = machine_opts[self.LABEL]
                machine.platform = machine_opts["platform"]
                machine.options = machine_opts.get("options", "")
                machine.tags = machine_opts.get("tags")
                machine.ip = machine_opts["ip"]

                # If configured, use specific network interface for this
                # machine, else use the default value.
                if machine_opts.get("interface"):
                    machine.interface = machine_opts["interface"]
                else:
                    machine.interface = mmanager_opts.get("interface")

                # If configured, use specific snapshot name, else leave it
                # empty and use default behaviour.
                machine.snapshot = machine_opts.get("snapshot")

                # If configured, use specific resultserver IP and port,
                # else use the default value.
                opt_resultserver = self.options_globals.resultserver

                # the resultserver port might have been dynamically changed
                #  -> get the current one from the resultserver singleton
                opt_resultserver.port = self._get_resultserver_port()

                ip = machine_opts.get("resultserver_ip", opt_resultserver.ip)
                port = machine_opts.get("resultserver_port", opt_resultserver.port)

                machine.resultserver_ip = ip
                machine.resultserver_port = port

                # Strip parameters.
                for key, value in machine.items():
                    if value and isinstance(value, basestring):
                        machine[key] = value.strip()

                self.db.add_machine(name=machine.id,
                                    label=machine.label,
                                    ip=machine.ip,
                                    platform=machine.platform,
                                    options=machine.options,
                                    tags=machine.tags,
                                    interface=machine.interface,
                                    snapshot=machine.snapshot,
                                    resultserver_ip=ip,
                                    resultserver_port=port)
            except (AttributeError, CuckooOperationalError) as e:
                log.warning("Configuration details about machine %s "
                            "are missing: %s", machine_id.strip(), e)
                continue

    def _initialize_check(self):
        """Runs checks against virtualization software when a machine manager
        is initialized.
        @note: in machine manager modules you may override or superclass
               his method.
        @raise CuckooMachineError: if a misconfiguration or a unkown vm state
                                   is found.
        """
        try:
            configured_vms = self._list()
        except NotImplementedError:
            return

        for machine in self.machines():
            # If this machine is already in the "correct" state, then we
            # go on to the next machine.
            if machine.label in configured_vms and \
                    self._status(machine.label) in [self.POWEROFF, self.ABORTED]:
                continue

            # This machine is currently not in its correct state, we're going
            # to try to shut it down. If that works, then the machine is fine.
            try:
                self.stop(machine.label)
            except CuckooMachineError as e:
                msg = "Please update your configuration. Unable to shut " \
                      "'{0}' down or find the machine in its proper state:" \
                      " {1}".format(machine.label, e)
                raise CuckooCriticalError(msg)

        if not self.options_globals.timeouts.vm_state:
            raise CuckooCriticalError("Virtual machine state change timeout "
                                      "setting not found, please add it to "
                                      "the config file.")

    def machines(self):
        """List virtual machines.
        @return: virtual machines list
        """
        return self.db.list_machines()

    def availables(self):
        """How many machines are free.
        @return: free machines count.
        """
        return self.db.count_machines_available()

    def acquire(self, machine_id=None, platform=None, tags=None):
        """Acquire a machine to start analysis.
        @param machine_id: machine ID.
        @param platform: machine platform.
        @param tags: machine tags
        @return: machine or None.
        """
        if machine_id:
            return self.db.lock_machine(label=machine_id)
        elif platform:
            return self.db.lock_machine(platform=platform, tags=tags)
        else:
            return self.db.lock_machine(tags=tags)

    def release(self, label=None):
        """Release a machine.
        @param label: machine name.
        """
        self.db.unlock_machine(label)

    def running(self):
        """Returns running virtual machines.
        @return: running virtual machines list.
        """
        return self.db.list_machines(locked=True)

    def shutdown(self):
        """Shutdown the machine manager. Kills all alive machines.
        @raise CuckooMachineError: if unable to stop machine.
        """
        if len(self.running()) > 0:
            log.info("Still %s guests alive. Shutting down...",
                     len(self.running()))
            for machine in self.running():
                try:
                    self.stop(machine.label)
                except CuckooMachineError as e:
                    log.warning("Unable to shutdown machine %s, please check "
                                "manually. Error: %s", machine.label, e)

    def set_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        self.db.set_machine_status(label, status)

    def start(self, label, task):
        """Start a machine.
        @param label: machine name.
        @param task: task object.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def stop(self, label=None):
        """Stop a machine.
        @param label: machine name.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def _list(self):
        """Lists virtual machines configured.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def dump_memory(self, label, path):
        """Takes a memory dump of a machine.
        @param path: path to where to store the memory dump.
        """
        raise NotImplementedError

    def _wait_status(self, label, state):
        """Waits for a vm status.
        @param label: virtual machine name.
        @param state: virtual machine status, accepts multiple states as list.
        @raise CuckooMachineError: if default waiting timeout expire.
        """
        # This block was originally suggested by Loic Jaquemet.
        waitme = 0
        try:
            current = self._status(label)
        except NameError:
            return

        if isinstance(state, str):
            state = [state]

        while current not in state:
            log.debug("Waiting %i cuckooseconds for machine %s to switch "
                      "to status %s", waitme, label, state)
            if waitme > int(self.options_globals.timeouts.vm_state):
                raise CuckooMachineError("Timeout hit while for machine {0} "
                                         "to change status".format(label))
            time.sleep(1)
            waitme += 1
            current = self._status(label)

class LibVirtMachinery(Machinery):
    """Libvirt based machine manager.

    If you want to write a custom module for a virtualization software
    supported by libvirt you have just to inherit this machine manager and
    change the connection string.
    """

    # VM states.
    RUNNING = "running"
    PAUSED = "paused"
    POWEROFF = "poweroff"
    ERROR = "machete"
    ABORTED = "abort"

    def __init__(self):
        if not HAVE_LIBVIRT:
            raise CuckooDependencyError("Unable to import libvirt")

        super(LibVirtMachinery, self).__init__()

    def initialize(self, module):
        """Initialize machine manager module. Override default to set proper
        connection string.
        @param module:  machine manager module
        """
        super(LibVirtMachinery, self).initialize(module)

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if libvirt version is not supported.
        """
        # Version checks.
        if not self._version_check():
            raise CuckooMachineError("Libvirt version is not supported, "
                                     "please get an updated version")

        # Preload VMs
        self.vms = self._fetch_machines()

        # Base checks. Also attempts to shutdown any machines which are
        # currently still active.
        super(LibVirtMachinery, self)._initialize_check()

    def start(self, label, task):
        """Starts a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start virtual machine.
        """
        log.debug("Starting machine %s", label)

        if self._status(label) != self.POWEROFF:
            msg = "Trying to start a virtual machine that has not " \
                  "been turned off {0}".format(label)
            raise CuckooMachineError(msg)

        conn = self._connect()

        vm_info = self.db.view_machine_by_label(label)

        snapshot_list = self.vms[label].snapshotListNames(flags=0)

        # If a snapshot is configured try to use it.
        if vm_info.snapshot and vm_info.snapshot in snapshot_list:
            # Revert to desired snapshot, if it exists.
            log.debug("Using snapshot {0} for virtual machine "
                      "{1}".format(vm_info.snapshot, label))
            try:
                vm = self.vms[label]
                snapshot = vm.snapshotLookupByName(vm_info.snapshot, flags=0)
                self.vms[label].revertToSnapshot(snapshot, flags=0)
            except libvirt.libvirtError:
                msg = "Unable to restore snapshot {0} on " \
                      "virtual machine {1}".format(vm_info.snapshot, label)
                raise CuckooMachineError(msg)
            finally:
                self._disconnect(conn)
        elif self._get_snapshot(label):
            snapshot = self._get_snapshot(label)
            log.debug("Using snapshot {0} for virtual machine "
                      "{1}".format(snapshot.getName(), label))
            try:
                self.vms[label].revertToSnapshot(snapshot, flags=0)
            except libvirt.libvirtError:
                raise CuckooMachineError("Unable to restore snapshot on "
                                         "virtual machine {0}".format(label))
            finally:
                self._disconnect(conn)
        else:
            self._disconnect(conn)
            raise CuckooMachineError("No snapshot found for virtual machine "
                                     "{0}".format(label))

        # Check state.
        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine. Kill them all.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop virtual machine.
        """
        log.debug("Stopping machine %s", label)

        if self._status(label) == self.POWEROFF:
            raise CuckooMachineError("Trying to stop an already stopped "
                                     "machine {0}".format(label))

        # Force virtual machine shutdown.
        conn = self._connect()
        try:
            if not self.vms[label].isActive():
                log.debug("Trying to stop an already stopped machine %s. "
                          "Skip", label)
            else:
                self.vms[label].destroy()  # Machete's way!
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error stopping virtual machine "
                                     "{0}: {1}".format(label, e))
        finally:
            self._disconnect(conn)
        # Check state.
        self._wait_status(label, self.POWEROFF)

    def shutdown(self):
        """Override shutdown to free libvirt handlers - they print errors."""
        super(LibVirtMachinery, self).shutdown()

        # Free handlers.
        self.vms = None

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """
        log.debug("Dumping memory for machine %s", label)

        conn = self._connect()
        try:
            # Resolve permission issue as libvirt creates the file as
            # root/root in mode 0600, preventing us from reading it. This
            # supposedly still doesn't allow us to remove it, though..
            open(path, "wb").close()
            self.vms[label].coreDump(path, flags=libvirt.VIR_DUMP_MEMORY_ONLY)
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error dumping memory virtual machine "
                                     "{0}: {1}".format(label, e))
        finally:
            self._disconnect(conn)

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s", label)

        # Stetes mapping of python-libvirt.
        # virDomainState
        # VIR_DOMAIN_NOSTATE = 0
        # VIR_DOMAIN_RUNNING = 1
        # VIR_DOMAIN_BLOCKED = 2
        # VIR_DOMAIN_PAUSED = 3
        # VIR_DOMAIN_SHUTDOWN = 4
        # VIR_DOMAIN_SHUTOFF = 5
        # VIR_DOMAIN_CRASHED = 6
        # VIR_DOMAIN_PMSUSPENDED = 7

        conn = self._connect()
        try:
            state = self.vms[label].state(flags=0)
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error getting status for virtual "
                                     "machine {0}: {1}".format(label, e))
        finally:
            self._disconnect(conn)

        if state:
            if state[0] == 1:
                status = self.RUNNING
            elif state[0] == 3:
                status = self.PAUSED
            elif state[0] == 4 or state[0] == 5:
                status = self.POWEROFF
            else:
                status = self.ERROR

        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError("Unable to get status for "
                                     "{0}".format(label))

    def _connect(self):
        """Connects to libvirt subsystem.
        @raise CuckooMachineError: when unable to connect to libvirt.
        """
        # Check if a connection string is available.
        if not self.dsn:
            raise CuckooMachineError("You must provide a proper "
                                     "connection string")

        try:
            return libvirt.open(self.dsn)
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot connect to libvirt")

    def _disconnect(self, conn):
        """Disconnects to libvirt subsystem.
        @raise CuckooMachineError: if cannot disconnect from libvirt.
        """
        try:
            conn.close()
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot disconnect from libvirt")

    def _fetch_machines(self):
        """Fetch machines handlers.
        @return: dict with machine label as key and handle as value.
        """
        vms = {}
        for vm in self.machines():
            vms[vm.label] = self._lookup(vm.label)
        return vms

    def _lookup(self, label):
        """Search for a virtual machine.
        @param conn: libvirt connection handle.
        @param label: virtual machine name.
        @raise CuckooMachineError: if virtual machine is not found.
        """
        conn = self._connect()
        try:
            vm = conn.lookupByName(label)
        except libvirt.libvirtError:
                raise CuckooMachineError("Cannot find machine "
                                         "{0}".format(label))
        finally:
            self._disconnect(conn)
        return vm

    def _list(self):
        """List available virtual machines.
        @raise CuckooMachineError: if unable to list virtual machines.
        """
        conn = self._connect()
        try:
            names = conn.listDefinedDomains()
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot list domains")
        finally:
            self._disconnect(conn)
        return names

    def _version_check(self):
        """Check if libvirt release supports snapshots.
        @return: True or false.
        """
        if libvirt.getVersion() >= 8000:
            return True
        else:
            return False

    def _get_snapshot(self, label):
        """Get current snapshot for virtual machine
        @param label: virtual machine name
        @return None or current snapshot
        @raise CuckooMachineError: if cannot find current snapshot or
                                   when there are too many snapshots available
        """
        def _extract_creation_time(node):
            """Extracts creation time from a KVM vm config file.
            @param node: config file node
            @return: extracted creation time
            """
            xml = ET.fromstring(node.getXMLDesc(flags=0))
            return xml.findtext("./creationTime")

        snapshot = None
        conn = self._connect()
        try:
            vm = self.vms[label]

            # Try to get the currrent snapshot, otherwise fallback on the latest
            # from config file.
            if vm.hasCurrentSnapshot(flags=0):
                snapshot = vm.snapshotCurrent(flags=0)
            else:
                log.debug("No current snapshot, using latest snapshot")

                # No current snapshot, try to get the last one from config file.
                snapshot = sorted(vm.listAllSnapshots(flags=0),
                                  key=_extract_creation_time,
                                  reverse=True)[0]
        except libvirt.libvirtError:
            raise CuckooMachineError("Unable to get snapshot for "
                                     "virtual machine {0}".format(label))
        finally:
            self._disconnect(conn)

        return snapshot

class Processing(object):
    """Base abstract class for processing module."""
    order = 1
    enabled = True

    def __init__(self):
        self.analysis_path = ""
        self.baseline_path = ""
        self.logs_path = ""
        self.task = None
        self.options = None
        self.results = {}

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task

    def set_baseline(self, baseline_path):
        """Set the path to the baseline directory."""
        self.baseline_path = baseline_path

    def set_path(self, analysis_path):
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.log_path = os.path.join(self.analysis_path, "analysis.log")
        self.cuckoolog_path = os.path.join(self.analysis_path, "cuckoo.log")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path,
                                                       "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.dropped_meta_path = os.path.join(self.analysis_path, "files.json")
        self.package_files = os.path.join(self.analysis_path, "package_files")
        self.buffer_path = os.path.join(self.analysis_path, "buffer")
        self.logs_path = os.path.join(self.analysis_path, "logs")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.pmemory_path = os.path.join(self.analysis_path, "memory")
        self.memory_path = os.path.join(self.analysis_path, "memory.dmp")
        self.mitmout_path = os.path.join(self.analysis_path, "mitm.log")
        self.mitmerr_path = os.path.join(self.analysis_path, "mitm.err")
        self.tlsmaster_path = os.path.join(self.analysis_path, "tlsmaster.txt")
        self.suricata_path = os.path.join(self.analysis_path, "suricata")
        self.network_path = os.path.join(self.analysis_path, "network")
        self.taskinfo_path = os.path.join(self.analysis_path, "task.json")

    def set_results(self, results):
        """Set the results - the fat dictionary."""
        self.results = results

    def run(self):
        """Start processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

class Signature(object):
    """Base class for Cuckoo signatures."""
    name = ""
    description = ""
    severity = 1
    order = 1
    categories = []
    families = []
    authors = []
    references = []
    platform = None
    alert = False
    enabled = True
    minimum = None
    maximum = None

    # Maximum amount of marks to record.
    markcount = 50

    # Basic filters to reduce the amount of events sent to this signature.
    filter_apinames = []
    filter_categories = []

    # If no on_call() handler is present and this field has been set, then
    # dispatch on a per-API basis to the accompanying API. That is, rather
    # than calling the generic on_call(), call, e.g., on_call_CreateFile().
    on_call_dispatch = False

    def __init__(self, caller):
        """
        @param caller: calling object. Stores results in caller.results
        """
        self.marks = []
        self.matched = False
        self._caller = caller

        # These are set by the caller, they represent the process identifier
        # and call index respectively.
        self.pid = None
        self.cid = None
        self.call = None

    def _check_value(self, pattern, subject, regex=False, all=False):
        """Checks a pattern against a given subject.
        @param pattern: string or expression to check for.
        @param subject: target of the check.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        ret = set()
        if regex:
            exp = re.compile(pattern, re.IGNORECASE)
            if isinstance(subject, list):
                for item in subject:
                    if exp.match(item):
                        ret.add(item)
            else:
                if exp.match(subject):
                    ret.add(subject)
        else:
            if isinstance(subject, list):
                for item in subject:
                    if item.lower() == pattern.lower():
                        ret.add(item)
            else:
                if subject == pattern:
                    ret.add(subject)

        # Return all elements.
        if all:
            return list(ret)
        # Return only the first element, if available. Otherwise return None.
        elif ret:
            return ret.pop()

    def get_results(self, key=None, default=None):
        if key:
            return self._caller.results.get(key, default)

        return self._caller.results

    def get_processes(self, name=None):
        """Get a list of processes.

        @param name: If set only return processes with that name.
        @return: List of processes or empty list
        """
        for item in self.get_results("behavior", {}).get("processes", []):
            if name is None or item["process_name"] == name:
                yield item

    def get_process_by_pid(self, pid=None):
        """Get a process by its process identifier.

        @param pid: pid to search for.
        @return: process.
        """
        for item in self.get_results("behavior", {}).get("processes", []):
            if item["pid"] == pid:
                return item

    def get_summary(self, key=None, default=[]):
        """Get one or all values related to the global summary."""
        summary = self.get_results("behavior", {}).get("summary", {})
        return summary.get(key, default) if key else summary

    def get_summary_generic(self, pid, actions):
        """Get generic info from summary.

        @param pid: pid of the process. None for all
        @param actions: A list of actions to get
        """
        ret = []
        for process in self.get_results("behavior", {}).get("generic", []):
            if pid is not None and process["pid"] != pid:
                continue

            for action in actions:
                if action in process["summary"]:
                    ret += process["summary"][action]
        return ret

    def get_files(self, pid=None, actions=None):
        """Get files read, queried, or written to optionally by a
        specific process.

        @param pid: the process or None for all
        @param actions: actions to search for. None is all
        @return: yields files

        """
        if actions is None:
            actions = [
                "file_opened", "file_written",
                "file_read", "file_deleted",
                "file_exists", "file_failed",
            ]

        return self.get_summary_generic(pid, actions)

    def get_dll_loaded(self, pid=None):
        """Get DLLs loaded by a specific process.

        @param pid: the process or None for all
        @return: yields DLLs loaded

        """
        return self.get_summary_generic(pid, ["dll_loaded"])

    def get_keys(self, pid=None, actions=None):
        """Get registry keys.

        @param pid: The pid to look in or None for all.
        @param actions: the actions as a list.
        @return: yields registry keys

        """
        if actions is None:
            actions = [
                "regkey_opened", "regkey_written",
                "regkey_read", "regkey_deleted",
            ]

        return self.get_summary_generic(pid, actions)

    def check_file(self, pattern, regex=False, actions=None, pid=None,
                   all=False):
        """Checks for a file being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param actions: a list of key actions to use.
        @param pid: The process id to check. If it is set to None, all
                    processes will be checked.
        @return: boolean with the result of the check.
        """
        if actions is None:
            actions = [
                "file_opened", "file_written",
                "file_read", "file_deleted",
                "file_exists", "file_failed",
            ]

        return self._check_value(pattern=pattern,
                                 subject=self.get_files(pid, actions),
                                 regex=regex,
                                 all=all)

    def check_dll_loaded(self, pattern, regex=False, actions=None, pid=None,
                         all=False):
        """Checks for DLLs being loaded.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param pid: The process id to check. If it is set to None, all
                    processes will be checked.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.get_dll_loaded(pid),
                                 regex=regex,
                                 all=all)

    def check_key(self, pattern, regex=False, actions=None, pid=None,
                  all=False):
        """Checks for a registry key being accessed.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param actions: a list of key actions to use.
        @param pid: The process id to check. If it is set to None, all
                    processes will be checked.
        @return: boolean with the result of the check.
        """
        if actions is None:
            actions = [
                "regkey_written", "regkey_opened",
                "regkey_read", "regkey_deleted",
            ]

        return self._check_value(pattern=pattern,
                                 subject=self.get_keys(pid, actions),
                                 regex=regex,
                                 all=all)

    def get_mutexes(self, pid=None):
        """
        @param pid: Pid to filter for
        @return:List of mutexes
        """
        return self.get_summary_generic(pid, ["mutex"])

    def check_mutex(self, pattern, regex=False, all=False):
        """Checks for a mutex being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.get_mutexes(),
                                 regex=regex,
                                 all=all)

    def get_command_lines(self):
        """Retrieves all command lines used."""
        return self.get_summary("command_line")

    def get_wmi_queries(self):
        """Retrieves all executed WMI queries."""
        return self.get_summary("wmi_query")

    def get_net_generic(self, subtype):
        """Generic getting network data.

        @param subtype: subtype string to search for.
        """
        return self.get_results("network", {}).get(subtype, [])

    def get_net_hosts(self):
        """Returns a list of all hosts."""
        return self.get_net_generic("hosts")

    def get_net_domains(self):
        """Returns a list of all domains."""
        return self.get_net_generic("domains")

    def get_net_http(self):
        """Returns a list of all http data."""
        return self.get_net_generic("http")

    def get_net_http_ex(self):
        """Returns a list of all http data."""
        return \
            self.get_net_generic("http_ex") + self.get_net_generic("https_ex")

    def get_net_udp(self):
        """Returns a list of all udp data."""
        return self.get_net_generic("udp")

    def get_net_icmp(self):
        """Returns a list of all icmp data."""
        return self.get_net_generic("icmp")

    def get_net_irc(self):
        """Returns a list of all irc data."""
        return self.get_net_generic("irc")

    def get_net_smtp(self):
        """Returns a list of all smtp data."""
        return self.get_net_generic("smtp")

    def get_virustotal(self):
        """Returns the information retrieved from virustotal."""
        return self.get_results("virustotal", {})

    def get_volatility(self, module=None):
        """Returns the data that belongs to the given module."""
        volatility = self.get_results("memory", {})
        return volatility if module is None else volatility.get(module, {})

    def get_apkinfo(self, section=None, default={}):
        """Returns the apkinfo results for this analysis."""
        apkinfo = self.get_results("apkinfo", {})
        return apkinfo if section is None else apkinfo.get(section, default)

    def get_droidmon(self, section=None, default={}):
        """Returns the droidmon results for this analysis."""
        droidmon = self.get_results("droidmon", {})
        return droidmon if section is None else droidmon.get(section, default)

    def get_googleplay(self, section=None, default={}):
        """Returns the Google Play results for this analysis."""
        googleplay = self.get_results("googleplay", {})
        return googleplay if section is None else googleplay.get(section, default)

    def check_ip(self, pattern, regex=False, all=False):
        """Checks for an IP address being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.get_net_hosts(),
                                 regex=regex,
                                 all=all)

    def check_domain(self, pattern, regex=False, all=False):
        """Checks for a domain being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        domains = set()
        for item in self.get_net_domains():
            domains.add(item["domain"])

        return self._check_value(pattern=pattern,
                                 subject=list(domains),
                                 regex=regex,
                                 all=all)

    def check_url(self, pattern, regex=False, all=False):
        """Checks for a URL being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        urls = set()
        for item in self.get_net_http():
            urls.add(item["uri"])

        return self._check_value(pattern=pattern,
                                 subject=list(urls),
                                 regex=regex,
                                 all=all)

    def init(self):
        """Allow signatures to initialize themselves."""

    def mark_call(self, *args, **kwargs):
        """Mark the current call as explanation as to why this signature
        matched."""
        mark = {
            "type": "call",
            "pid": self.pid,
            "cid": self.cid,
            "call": self.call,
        }

        if args or kwargs:
            log.warning(
                "You have provided extra arguments to the mark_call() method "
                "which no longer supports doing so. Please report explicit "
                "IOCs through mark_ioc()."
            )

        self.marks.append(mark)

    def mark_ioc(self, category, ioc, description=None):
        """Mark an IOC as explanation as to why the current signature
        matched."""
        mark = {
            "type": "ioc",
            "category": category,
            "ioc": ioc,
            "description": description,
        }

        # Prevent duplicates.
        if mark not in self.marks:
            self.marks.append(mark)

    def mark_vol(self, plugin, **kwargs):
        """Mark output of a Volatility plugin as explanation as to why the
        current signature matched."""
        mark = {
            "type": "volatility",
            "plugin": plugin,
        }
        mark.update(kwargs)
        self.marks.append(mark)

    def mark(self, **kwargs):
        """Mark arbitrary data."""
        mark = {
            "type": "generic",
        }
        mark.update(kwargs)
        self.marks.append(mark)

    def has_marks(self, count=None):
        """Returns true if this signature has one or more marks."""
        if count is not None:
            return len(self.marks) >= count
        return not not self.marks

    def on_call(self, call, process):
        """Notify signature about API call. Return value determines
        if this signature is done or could still match.

        Only called if signature is "active".

        @param call: logged API call.
        @param process: proc object.
        """
        # Dispatch this call to a per-API specific handler.
        if self.on_call_dispatch:
            return getattr(self, "on_call_%s" % call["api"])(call, process)

        raise NotImplementedError

    def on_signature(self, signature):
        """Event yielded when another signatures has matched. Some signatures
        only take effect when one or more other signatures have matched as
        well.

        @param signature: The signature that just matched
        """

    def on_process(self, process):
        """Called on process change.

        Can be used for cleanup of flags, re-activation of the signature, etc.

        @param process: dictionary describing this process
        """

    def on_complete(self):
        """Signature is notified when all API calls have been processed."""

    def results(self):
        """Turn this signature into actionable results."""
        return dict(name=self.name,
                    description=self.description,
                    severity=self.severity,
                    families=self.families,
                    references=self.references,
                    marks=self.marks[:self.markcount],
                    markcount=len(self.marks))

class Report(object):
    """Base abstract class for reporting module."""
    order = 1

    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.task = None
        self.options = None

    def _get_analysis_path(self, subpath):
        return os.path.join(self.analysis_path, subpath)

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.conf_path = self._get_analysis_path("analysis.conf")
        self.file_path = os.path.realpath(self._get_analysis_path("binary"))
        self.reports_path = self._get_analysis_path("reports")
        self.shots_path = self._get_analysis_path("shots")
        self.pcap_path = self._get_analysis_path("dump.pcap")

        try:
            create_folder(folder=self.reports_path)
        except CuckooOperationalError as e:
            raise CuckooReportError(e)

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task

    def run(self):
        """Start report processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

class BehaviorHandler(object):
    """Base class for behavior handlers inside of BehaviorAnalysis."""
    key = "undefined"

    # Behavior event types this handler is interested in.
    event_types = []

    def __init__(self, behavior_analysis):
        self.analysis = behavior_analysis

    def handles_path(self, logpath):
        """Needs to return True for the log files this handler wants to
        process."""
        return False

    def parse(self, logpath):
        """Called after handles_path succeeded, should generate behavior
        events."""
        raise NotImplementedError

    def handle_event(self, event):
        """Handle an event that gets passed down the stack."""
        raise NotImplementedError

    def run(self):
        """Return the handler specific structure, gets placed into
        behavior[self.key]."""
        raise NotImplementedError

class ProtocolHandler(object):
    """Abstract class for protocol handlers coming out of the analysis."""
    def __init__(self, handler, version=None):
        self.handler = handler
        self.version = version

    def init(self):
        pass

    def close(self):
        pass
