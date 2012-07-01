# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import socket
import ConfigParser

from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.constants import CUCKOO_ROOT

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
        self.config_path = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % module_name)
        self.config.read(self.config_path)
        
        machines_list = self.config.get(self.module_name, "machines").strip().split(",")
        for machine_id in machines_list:
            machine = Dictionary()
            machine.id = machine_id
            machine.label = self.config.get(machine_id, "label")
            machine.platform = self.config.get(machine_id, "platform")
            machine.ip = self.config.get(machine_id, "ip")
            machine.locked = False
            machine.resolver = None
            try:
                machine.resolver = self.config.get(machine_id, "resolver")
            except:
                pass
            
            if (not machine.resolver or machine.resolver == "") and machine.ip == "":
                raise CuckooMachineError("Machine %s was not configured with a resolver or IP address" % machine.label)

            self.machines.append(machine)

        # Checks if machines configured are really available.
        try:
            configured_vm = self._list()
            for machine in self.machines:
                if machine.label not in configured_vm:
                    raise CuckooMachineError("Configured machine %s was not detected or it's not in proper state" % machine.label)
        except NotImplementedError:
            pass

    def resolve(self, vm):
        ''' Resolve the VM's IP address using the vm's resolver
        this method can be overridden for other types of guest machine resolutions
        @param: vm whose ip needs to be resolved
        @raise CuckooMachineError: IP address could not be resolved
        '''
        if vm.resolver and isinstance(vm.resolver, str) and\
           vm.resolver == "dns":
           addrinfos = socket.getaddrinfo(vm.label, 80) # just use 80 as a default
           if len(addrinfos) > 0 and len(addrinfos[0]) > 4 and len(addrinfos[0][4]) > 1:
               vm.ip = addrinfos[0][4][0]
               return vm.ip
        raise CuckooMachineError("Unable to obtain the IP Address for the following machine: %s"%vm.label)

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
        """Returns running virutal machines.
        @return: running virtual machines list.
        """
        return [m for m in self.machines if m.locked]

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
        self.log_path = os.path.join(self.analysis_path, "analysis.log")
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.file_path = os.path.join(self.analysis_path, "binary")
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
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
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
