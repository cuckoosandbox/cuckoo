# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import logging
import time

import xml.etree.ElementTree as ET

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import Dictionary
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.resultserver import ResultServer

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
        self.options = None

    def set_task(self, task):
        self.task = task

    def set_machine(self, machine):
        self.machine = machine

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
                machine.tags = machine_opts.get("tags")
                machine.ip = machine_opts["ip"]

                # If configured, use specific network interface for this
                # machine, else use the default value.
                machine.interface = machine_opts.get("interface")

                # If configured, use specific snapshot name, else leave it
                # empty and use default behaviour.
                machine.snapshot = machine_opts.get("snapshot")

                # If configured, use specific resultserver IP and port,
                # else use the default value.
                opt_resultserver = self.options_globals.resultserver

                # the resultserver port might have been dynamically changed
                #  -> get the current one from the resultserver singelton
                opt_resultserver.port = ResultServer().port

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
                                    tags=machine.tags,
                                    interface=machine.interface,
                                    snapshot=machine.snapshot,
                                    resultserver_ip=ip,
                                    resultserver_port=port)
            except (AttributeError, CuckooOperationalError) as e:
                log.warning("Configuration details about machine %s "
                            "are missing: %s", machine_id, e)
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

    def start(self, label=None):
        """Start a machine.
        @param label: machine name.
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

    def start(self, label):
        """Starts a virtual machine.
        @param label: virtual machine name.
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
        self.logs_path = ""
        self.task = None
        self.options = None

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

    def set_path(self, analysis_path):
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.log_path = os.path.join(self.analysis_path, "analysis.log")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path,
                                                       "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.logs_path = os.path.join(self.analysis_path, "logs")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.pmemory_path = os.path.join(self.analysis_path, "memory")
        self.memory_path = os.path.join(self.analysis_path, "memory.dmp")

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
    categories = []
    families = []
    authors = []
    references = []
    alert = False
    enabled = True
    minimum = None
    maximum = None

    # Higher order will be processed later (only for non-evented signatures)
    # this can be used for having meta-signatures that check on other lower-
    # order signatures being matched
    order = 0

    evented = False
    filter_processnames = set()
    filter_apinames = set()
    filter_categories = set()

    def __init__(self, results=None):
        self.data = []
        self.results = results
        self._current_call_cache = None
        self._current_call_dict = None

    def _check_value(self, pattern, subject, regex=False):
        """Checks a pattern against a given subject.
        @param pattern: string or expression to check for.
        @param subject: target of the check.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        if regex:
            exp = re.compile(pattern, re.IGNORECASE)
            if isinstance(subject, list):
                for item in subject:
                    if exp.match(item):
                        return item
            else:
                if exp.match(subject):
                    return subject
        else:
            if isinstance(subject, list):
                for item in subject:
                    if item == pattern:
                        return item
            else:
                if subject == pattern:
                    return subject

        return None

    def check_file(self, pattern, regex=False):
        """Checks for a file being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        subject = self.results["behavior"]["summary"]["files"]
        return self._check_value(pattern=pattern,
                                 subject=subject,
                                 regex=regex)

    def check_key(self, pattern, regex=False):
        """Checks for a registry key being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        subject = self.results["behavior"]["summary"]["keys"]
        return self._check_value(pattern=pattern,
                                 subject=subject,
                                 regex=regex)

    def check_mutex(self, pattern, regex=False):
        """Checks for a mutex being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        subject = self.results["behavior"]["summary"]["mutexes"]
        return self._check_value(pattern=pattern,
                                 subject=subject,
                                 regex=regex)

    def check_api(self, pattern, process=None, regex=False):
        """Checks for an API being called.
        @param pattern: string or expression to check for.
        @param process: optional filter for a specific process name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        # Loop through processes.
        for item in self.results["behavior"]["processes"]:
            # Check if there's a process name filter.
            if process:
                if item["process_name"] != process:
                    continue

            # Loop through API calls.
            for call in item["calls"]:
                # Check if the name matches.
                if self._check_value(pattern=pattern,
                                     subject=call["api"],
                                     regex=regex):
                    return call["api"]

        return None

    def check_argument_call(self,
                            call,
                            pattern,
                            name=None,
                            api=None,
                            category=None,
                            regex=False):
        """Checks for a specific argument of an invoked API.
        @param call: API call information.
        @param pattern: string or expression to check for.
        @param name: optional filter for the argument name.
        @param api: optional filter for the API function name.
        @param category: optional filter for a category name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        # Check if there's an API name filter.
        if api:
            if call["api"] != api:
                return False

        # Check if there's a category filter.
        if category:
            if call["category"] != category:
                return False

        # Loop through arguments.
        for argument in call["arguments"]:
            # Check if there's an argument name filter.
            if name:
                if argument["name"] != name:
                    continue

            # Check if the argument value matches.
            if self._check_value(pattern=pattern,
                                 subject=argument["value"],
                                 regex=regex):
                return argument["value"]

        return False

    def check_argument(self,
                       pattern,
                       name=None,
                       api=None,
                       category=None,
                       process=None,
                       regex=False):
        """Checks for a specific argument of an invoked API.
        @param pattern: string or expression to check for.
        @param name: optional filter for the argument name.
        @param api: optional filter for the API function name.
        @param category: optional filter for a category name.
        @param process: optional filter for a specific process name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        # Loop through processes.
        for item in self.results["behavior"]["processes"]:
            # Check if there's a process name filter.
            if process:
                if item["process_name"] != process:
                    continue

            # Loop through API calls.
            for call in item["calls"]:
                r = self.check_argument_call(call, pattern, name,
                                             api, category, regex)
                if r:
                    return r

        return None

    def check_ip(self, pattern, regex=False):
        """Checks for an IP address being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.results["network"]["hosts"],
                                 regex=regex)

    def check_domain(self, pattern, regex=False):
        """Checks for a domain being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        if "domains" not in self.results["network"]:
            return None

        for item in self.results["network"]["domains"]:
            if self._check_value(pattern=pattern,
                                 subject=item["domain"],
                                 regex=regex):
                return item

        return None

    def check_url(self, pattern, regex=False):
        """Checks for a URL being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        for item in self.results["network"]["http"]:
            if self._check_value(pattern=pattern,
                                 subject=item["uri"],
                                 regex=regex):
                return item

        return None

    def get_argument(self, call, name):
        """Retrieves the value of a specific argument from an API call.
        @param call: API call object.
        @param name: name of the argument to retrieve.
        @return: value of the required argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self._current_call_cache:
            self._current_call_cache = call
            self._current_call_dict = dict()

            for argument in call["arguments"]:
                self._current_call_dict[argument["name"]] = argument["value"]

        # Return the required argument.
        if name in self._current_call_dict:
            return self._current_call_dict[name]

        return None

    def add_match(self, process, type, match):
        """Adds a match to the signature data.
        @param process: The process triggering the match.
        @param type: The type of matching data (ex: 'api', 'mutex', 'file', etc.)
        @param match: Value or array of values triggering the match.
        """
        signs = []
        if isinstance(match, list):
            for item in match:
                signs.append({ 'type': type, 'value': item })
        else:
            signs.append({ 'type': type, 'value': match })

        process_summary = None
        if process:
            process_summary = {}
            process_summary['process_name'] = process['process_name']
            process_summary['process_id'] = process['process_id']

        self.data.append({ 'process': process_summary, 'signs': signs })

    def has_matches(self):
        """Returns true if there is matches (data is not empty)
        @return: boolean indicating if there is any match registered
        """
        return len(self.data) > 0

    def on_call(self, call, process):
        """Notify signature about API call. Return value determines
        if this signature is done or could still match.
        @param call: logged API call.
        @param process: process doing API call.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def on_complete(self):
        """Evented signature is notified when all API calls are done.
        @return: Match state.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def run(self):
        """Start signature processing.
        @param results: analysis results.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def as_result(self):
        """Properties as a dict (for results).
        @return: result dictionary.
        """
        return dict(
            name=self.name,
            description=self.description,
            severity=self.severity,
            references=self.references,
            data=self.data,
            alert=self.alert,
            families=self.families
        )

class Report(object):
    """Base abstract class for reporting module."""
    order = 1

    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.task = None
        self.options = None

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path,
                                                       "binary"))
        self.reports_path = os.path.join(self.analysis_path, "reports")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")

        try:
            create_folder(folder=self.reports_path)
        except CuckooOperationalError as e:
            CuckooReportError(e)

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
