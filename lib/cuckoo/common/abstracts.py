# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import ConfigParser

from lib.cuckoo.common.exceptions import CuckooMachineError


class Dictionary(dict):
    """Cuckko custom dict."""
    
    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class MachineManager(object):
    """Base abstract class for analysis machine manager."""

    def __init__(self):
        self.module_name = ""
        self.config_path = ""
        self.config = ConfigParser.ConfigParser()
        self.options = {}
        self.machines = []

    def initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        self.module_name = module_name
        self.config_path = os.path.join("conf", "%s.conf" % module_name)
        self.config.read(self.config_path)

        machines_list = self.config.get(self.module_name, "machines").strip().split(",")
        for machine_id in machines_list:
            machine = Dictionary()
            machine.id = machine_id
            machine.label = self.config.get(machine_id, "label")
            machine.platform = self.config.get(machine_id, "platform")
            machine.ip = self.config.get(machine_id, "ip")
            machine.locked = False
            self.machines.append(machine)

        # Checks if machines configured are really available.
        try:
            configured_vm = self._list()
            for machine in self.machines:
                if machine.label not in configured_vm:
                    raise CuckooMachineError("Configured VM %s was not detected" % machine.label)
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

    def acquire(self, label=None, platform=None):
        """Acquire a machine to start analysis.
        @param label: machine name.
        @param platform: machine platform.
        @return: machine or None.
        """
        if label:
            for machine in self.machines:
                if machine.label == label and not machine.locked:
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

    def __init__(self):
        self.analysis_path = ""
        self.logs_path = ""

    def set_path(self, analysis_path):
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.log_path = os.path.join(analysis_path, "analysis.log")
        self.conf_path = os.path.join(analysis_path, "analysis.conf")
        self.file_path = os.path.join(analysis_path, "binary")
        self.dropped_path = os.path.join(analysis_path, "files")
        self.logs_path = os.path.join(analysis_path, "logs")
        self.shots_path = os.path.join(analysis_path, "shots")
        self.pcap_path = os.path.join(analysis_path, "dump.pcap")

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
    references = []
    alert = False
    enabled = True

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

    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.options = None

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.reports_path = os.path.join(self.analysis_path, "reports")

        if not os.path.exists(self.reports_path):
            os.mkdir(self.reports_path)

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
