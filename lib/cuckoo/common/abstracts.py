# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooOperationalError, CuckooReportError
from lib.cuckoo.common.objects import Dictionary
from lib.cuckoo.common.utils import create_folder

log = logging.getLogger(__name__)

class MachineManager(object):
    """Base abstract class for analysis machine manager."""

    def __init__(self):
        self.module_name = ""
        self.options = None
        self.machines = []

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
            try:
                machine_opts = self.options.get(machine_id.strip())
                machine = Dictionary()
                machine.id = machine_id.strip()
                machine.label = machine_opts["label"].strip()
                machine.platform = machine_opts["platform"].strip()
                machine.ip = machine_opts["ip"].strip()
                machine.locked = False
                self.machines.append(machine)
            except (AttributeError, CuckooOperationalError):
                log.warning("Configuration details about machine %s are missing. Continue" % machine_id)
                continue

    def _initialize_check(self):
        """Runs checks against virtualization software when a machine manager is initialized.
        @note: in machine manager modules you may override or superclass this method.
        @raise CuckooMachineError: if a misconfiguration or a unkown vm state is found.
        """
        try:
            configured_vm = self._list()
            for machine in self.machines:
                if machine.label not in configured_vm:
                    raise CuckooMachineError("Configured machine %s was not detected or it's not in proper state" % machine.label)
        except NotImplementedError:
            pass

    def availables(self):
        """How many machines are free.
        @return: free machines count.
        """
        count = 0
        for machine in self.machines:
            if not machine.locked:
                count += 1

        return count

    def acquire(self, machine_id=None, platform=None):
        """Acquire a machine to start analysis.
        @param machine_id: machine ID.
        @param platform: machine platform.
        @return: machine or None.
        """
        if machine_id:
            for machine in self.machines:
                if machine.id == machine_id and not machine.locked:
                    machine.locked = True
                    return machine
        elif platform:
            for machine in self.machines:
                if machine.platform == platform and not machine.locked:
                    machine.locked = True
                    return machine
        else:
            for machine in self.machines:
                if not machine.locked:
                    machine.locked = True
                    return machine

        return None

    def release(self, label=None):
        """Release a machine.
        @param label: machine name.
        """
        if label:
            for machine in self.machines:
                if machine.label == label:
                    machine.locked = False

    def running(self):
        """Returns running virtual machines.
        @return: running virtual machines list.
        """
        return [m for m in self.machines if m.locked]

    def shutdown(self):
        """Shutdown the machine manager. Kills all alive machines.
        @raise CuckooMachineError: if unable to stop machine.
        """
        if len(self.running()) > 0:
            log.info("Still %s guests alive. Shutting down" % len(self.running()))
            for machine in self.running():
                try:
                    self.stop(machine.label)
                except CuckooMachineError as e:
                    log.error("Unable to shutdown machine %s, please check manually. Error: %s" % (machine.label, e))

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
        self.file_path = os.path.realpath(os.path.join(self.analysis_path, "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.logs_path = os.path.join(self.analysis_path, "logs")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")

    def run(self):
        """Start processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

class Signature(object):
    """Base abstract class for signature."""

    name = ""
    description = ""
    severity = 1
    categories = []
    authors = []
    references = []
    alert = False
    enabled = True
    minimum = None
    maximum = None

    def __init__(self):
        self.data = []

    def run(self, results=None):
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
