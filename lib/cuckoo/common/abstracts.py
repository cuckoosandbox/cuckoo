# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import logging
import time

from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import Dictionary
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

class MachineManager(object):
    """Base abstract class for analysis machine manager."""

    def __init__(self):
        self.module_name = ""
        self.options = None
        self.options_globals = Config(os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"))
        # Database pointer.
        self.db = Database()
        # Machine table is cleaned to be filled from configuration file at each start.
        self.db.clean_machines()

    def set_options(self, options):
        """Set machine manager options.
        @param options: machine manager options dict.
        """
        self.options = options

    def initialize(self, module_name):
        """Read and load machines configuration, try to check the configuration.
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
            # Parse from configuration file.
            try:
                machine_opts = self.options.get(machine_id.strip())
                machine = Dictionary()
                machine.id = machine_id.strip()
                machine.label = machine_opts["label"].strip()
                machine.platform = machine_opts["platform"].strip()
                machine.ip = machine_opts["ip"].strip()
                # Insert in db.
                self.db.add_machine(name=machine.id,
                                    label=machine.label,
                                    ip=machine.ip,
                                    platform=machine.platform)
            except (AttributeError, CuckooOperationalError):
                log.warning("Configuration details about machine %s are "
                            "missing. Continue" % machine_id)
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
            configured_vm = self._list()
        except NotImplementedError:
            return

        for machine in self.machines():
            if machine.label not in configured_vm:
                raise CuckooCriticalError("Configured machine %s was not "
                    "detected or it's not in proper state" % machine.label)

        # Options check.
        if not self.options_globals.timeouts.vm_state:
            raise CuckooCriticalError("Virtual machine state change timeout setting not found, please add it to the config file")


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

    def acquire(self, machine_id=None, platform=None):
        """Acquire a machine to start analysis.
        @param machine_id: machine ID.
        @param platform: machine platform.
        @return: machine or None.
        """
        if machine_id:
            return self.db.lock_machine(name=machine_id)
        elif platform:
            return self.db.lock_machine(platform=platform)
        else:
            return self.db.lock_machine()

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
        if self.running().count() > 0:
            log.info("Still %s guests alive. Shutting down" % self.running().count())
            for machine in self.running():
                try:
                    self.stop(machine.label)
                except CuckooMachineError as e:
                    log.error("Unable to shutdown machine %s, please check "
                              "manually. Error: %s" % (machine.label, e))

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

    def dump_memory(self, path):
        """Takes a memory dump of a machine.
        @param path: path to where to store the memory dump.
        """
        raise NotImplementedError

    def _wait_status(self, label, state):
        """Waits for a vm status.
        @param label: virtual machine name.
        @param state: virtual machine status, accepts more than one states in a list.
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
            log.debug("Waiting %i cuckooseconds for vm %s to switch to status %s" % (waitme, label, state))
            if waitme > int(self.options_globals.timeouts.vm_state):
                raise CuckooMachineError("Waiting too much for vm %s status change. Please check manually" % label)
            time.sleep(1)
            waitme += 1
            current = self._status(label)

class LibVirtMachineManager(MachineManager):
    """Libvirt based machine manager.

    If you want to write a custom module for a virtualization software supported
    by libvirt you have just to inherit this machine manager and change the 
    connection string.
    """
    
    # VM states.
    RUNNING = "running"
    POWEROFF = "poweroff"
    ERROR = "machete"

    def __init__(self):
        try:
            global libvirt
            import libvirt
        except ImportError:
            raise CuckooDependencyError("Unable to import libvirt")
        super(LibVirtMachineManager, self).__init__()

    def initialize(self, module):
        """Initialize machine manager module. Ovverride defualt to set proper
        connection string.
        @param module:  machine manager module
        """
        super(LibVirtMachineManager, self).initialize(module)

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if libvirt version is not supported.
        """
        # Version checks.
        if not self._version_check():
            raise CuckooMachineError("Libvirt version is not supported, please get an updated version")
        # Preload VMs
        self.vms = self._fetch_machines()
        # Base checks.
        super(LibVirtMachineManager, self)._initialize_check()

    def start(self, label):
        """Starts a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start virtual machine.
        """
        log.debug("Staring vm %s" % label)
        
        if self._status(label) == self.RUNNING:
            raise CuckooMachineError("Trying to start an already started vm %s" % label)

        # Get current snapshot.
        conn = self._connect()

        try:
            snap = self.vms[label].hasCurrentSnapshot(flags=0)
        except libvirt.libvirtError:
            self._disconnect(conn)
            raise CuckooMachineError("Unable to get current snapshot for virtual machine %s" % label)

        # Revert to latest snapshot.
        if snap:
            try:
                current = self.vms[label].snapshotCurrent(flags=0)
                self.vms[label].revertToSnapshot(current, flags=0)
            except libvirt.libvirtError:
                raise CuckooMachineError("Unable to restore snapshot on virtual machine %s" % label)
            finally:
                self._disconnect(conn)
        else:
            self._disconnect(conn)
            raise CuckooMachineError("No snapshot found for virtual machine %s" % label)
        # Check state.
        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine. Kill them all.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop virtual machine.
        """
        log.debug("Stopping vm %s" % label)

        if self._status(label) == self.POWEROFF:
            raise CuckooMachineError("Trying to stop an already stopped vm %s" % label)

        # Force virtual machine shutdown.
        conn = self._connect()
        try:
            if not self.vms[label].isActive():
                log.debug("Trying to stop an already stopped vm %s. Skip" % label)
            else:
                self.vms[label].destroy() # Machete's way!
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error stopping virtual machine %s: %s" % (label, e))
        finally:
            self._disconnect(conn)
        # Check state.
        self._wait_status(label, self.POWEROFF)

    def shutdown(self):
        """Override shutdown to free libvirt handlers, anyway they print errors."""
        super(LibVirtMachineManager, self).shutdown()
        # Free handlers.
        self.vms = None

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """
        log.debug("Dumping memory for vm %s" % label)

        conn = self._connect()
        try:
            self.vms[label].coreDump(path, flags=libvirt.VIR_DUMP_MEMORY_ONLY)
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error dumping memory virtual machine %s: %s" % (label, e))
        finally:
            self._disconnect(conn)

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s"% label)
        
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
            raise CuckooMachineError("Error getting status for virtual machine %s: %s" % (label, e))
        finally:
            self._disconnect(conn)

        if state:
            if state[0] == 1 or state[0] == 3:
                status = self.RUNNING
            elif state[0] == 4 or state[0] == 5:
                status = self.POWEROFF
            else:
                status = self.ERROR

        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError("Unable to get status for %s" % label)

    def _connect(self):
        """Connects to libvirt subsystem.
        @raise CuckooMachineError: if cannot connect to libvirt or missing connection string.
        """
        # Check if a connection string is available.
        if not self.dsn:
            raise CuckooMachineError("You must provide a proper connection string")

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
                raise CuckooMachineError("Cannot found machine %s" % label)
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

class Processing(object):
    """Base abstract class for processing module."""
    order = 1
    enabled = True

    def __init__(self):
        self.analysis_path = ""
        self.logs_path = ""

    def set_path(self, analysis_path):
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.log_path = os.path.join(self.analysis_path, "analysis.log")
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path,
                                                       "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.logs_path = os.path.join(self.analysis_path, "logs")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
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

    def __init__(self, results=None):
        self.data = []
        self.results = results

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
            if type(subject) == list:
                for item in subject:
                    if exp.match(item):
                        return True
            else:
                if exp.match(subject):
                    return True
        else:
            if type(subject) == list:
                for item in subject:
                    if item == pattern:
                        return True
            else:
                if subject == pattern:
                    return True

        return False

    def check_file(self, pattern, regex=False):
        """Checks for a file being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.results["behavior"]["summary"]["files"],
                                 regex=regex)

    def check_key(self, pattern, regex=False):
        """Checks for a registry key being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.results["behavior"]["summary"]["keys"],
                                 regex=regex)

    def check_mutex(self, pattern, regex=False):
        """Checks for a mutex being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        return self._check_value(pattern=pattern,
                                 subject=self.results["behavior"]["summary"]["mutexes"],
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
                    return True

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
                # Check if there's an API name filter.
                if api:
                    if call["api"] != api:
                        continue

                # Check if there's a category filter.
                if category:
                    if call["category"] != category:
                        continue

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
                        return True

        return False

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
        for item in self.results["network"]["domains"]:
            if self._check_value(pattern=pattern,
                                 subject=item["domain"],
                                 regex=regex):
                return True

        return False

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
                return True

        return False

    def run(self):
        """Start signature processing.
        @param results: analysis results.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

class Report(object):
    """Base abstract class for reporting module."""
    order = 1

    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.options = None

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.reports_path = os.path.join(self.analysis_path, "reports")

        try:
            create_folder(folder=self.reports_path)
        except CuckooOperationalError as e:
            CuckooReportError(e)

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def run(self):
        """Start report processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError
