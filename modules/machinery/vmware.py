# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file was originally produced by Mike Tu.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import subprocess
import os.path
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VMware(Machinery):
    """Virtualization layer for VMware Workstation using vmrun utility."""

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """  
        if not self.options.vmware.path:
            raise CuckooMachineError("VMware vmrun path missing, "
                                     "please add it to vmware.conf")
        if not os.path.exists(self.options.vmware.path):
            raise CuckooMachineError("VMware vmrun not found in "
                                     "specified path %s" %
                                     self.options.vmware.path)
        # Consistency checks.
        for machine in self.machines():
            host, snapshot = self._get_host_and_snapshot(machine.label)
            self._check_vmx(host)
            self._check_snapshot(host, snapshot)
        # Base checks.
        super(VMware, self)._initialize_check()

    def _check_vmx(self, host):
        """Checks a vmx file
        @param host: file path
        @raise CuckooMachineError: if file not found or not ending with .vmx
        """
        if not host.endswith(".vmx"):
            raise CuckooMachineError("Wrong configuration: vm path not "
                                     "ending with .vmx: %s)" % host)
        if not os.path.exists(self.options.vmware.path):
            raise CuckooMachineError("Vm file %s not found" % host)

    def _check_snapshot(self, host, snapshot):
        """Checks snapshot existance.
        @param host: file path
        @param snapshot: snapshot name
        @raise CuckooMachineError: if snapshot not found
        """
        try:
            p = subprocess.Popen([self.options.vmware.path,
                                  "listSnapshots", host],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output, error = p.communicate()
            if output:
                if snapshot in output:
                    return True
                else:
                    return False
            else:
                raise CuckooMachineError("Unable to get snapshot list for %s. "
                                         "No output from "
                                         "`vmrun listSnapshots`" % host)
        except OSError as e:
            raise CuckooMachineError("Unable to get snapshot list for %s. "
                                     "Reason: %s" % (host, e))

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine identifier: path to vmx file.
        @raise CuckooMachineError: if unable to start.
        """
        host, snapshot = self._get_host_and_snapshot(label)

        # Preventive check
        if self._is_running(host):
            raise CuckooMachineError("Machine %s is already running" % host)

        self._revert(host, snapshot)

        time.sleep(3)

        log.debug("Starting vm %s" % host)
        try:
            p = subprocess.Popen([self.options.vmware.path,
                                  "start", host, self.options.vmware.mode],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            if self.options.vmware.mode.lower() == "gui":
                output, error = p.communicate()
                if output:
                    raise CuckooMachineError("Unable to start machine "
                                             "%s: %s" % (host, output))
        except OSError as e:
            mode = self.options.vmware.mode.upper()
            raise CuckooMachineError("Unable to start machine %s in %s "
                                     "mode: %s" % (host, mode, e))

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine identifier: path to vmx file
            (in older configurations it also includes current snapshot name).
        @raise CuckooMachineError: if unable to stop.
        """
        host, snapshot = self._get_host_and_snapshot(label)

        log.debug("Stopping vm %s" % host)
        if self._is_running(host):
            try:
                if subprocess.call([self.options.vmware.path,
                                    "stop",
                                    host,
                                    "hard"],  # Machete never wait.
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE):
                    raise CuckooMachineError("Error shutting down "
                                             "machine %s" % host)
            except OSError as e:
                raise CuckooMachineError("Error shutting down machine "
                                         "%s: %s" % (host, e))
        else:
            log.warning("Trying to stop an already stopped machine: %s" % host)

    def _revert(self, host, snapshot):
        """Revets machine to snapshot.
        @param host: file path
        @param snapshot: snapshot name
        @raise CuckooMachineError: if unable to revert
        """
        log.debug("Revert snapshot for vm %s" % host)
        try:
            if subprocess.call([self.options.vmware.path,
                               "revertToSnapshot",
                               host,
                               snapshot],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("Unable to revert snapshot for "
                                         "machine %s: vmrun exited with "
                                         "error" % host)
        except OSError as e:
            raise CuckooMachineError("Unable to revert snapshot for "
                                     "machine %s: %s" % (host, e))

    def _is_running(self, host):
        """Checks if host is running.
        @param host: file path
        @return: running status
        """
        try:
            p = subprocess.Popen([self.options.vmware.path, "list"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output, error = p.communicate()
            if output:
                if host in output:
                    return True
                else:
                    return False
            else:
                raise CuckooMachineError("Unable to check running status "
                                         "for %s. No output from "
                                         "`vmrun list`" % host)
        except OSError as e:
            raise CuckooMachineError("Unable to check running status for %s. "
                                     "Reason: %s" % (host, e))

    def _parse_label(self, label):
        """Parse configuration file label.
        @param label: configuration option from config file
        @return: tuple of host file path and snapshot name
        """
        opts = label.strip().split(",")
        if len(opts) != 2:
            raise CuckooMachineError("Wrong label syntax for %s in "
                                     "vmware.conf: %s" % label)
        label = opts[0].strip()
        snapshot = opts[1].strip()
        return label, snapshot
    
    def _get_host_and_snapshot(self, label):
        """Get host and snapshot for a given label
        New configuration files have a specific 'snapshot' option, while
        older configuration files have a label in the format:
        'file.vmx,Snapshot'.
        @param label: configuration option from config file
        """
        vm_info = self.db.view_machine_by_label(label)
        
        if vm_info.snapshot:
            host = label.split(',')[0] 
            # Make sure to exclude any snapshot name from older conf files
            # if you also have the new option parameter
            snapshot = vm_info.snapshot
        else:
            # Keep support for older conf files
            host, snapshot = self._parse_label(label)
            log.warning("Deprecation warning: your vmware configuartion "
                        "file is using old snaphost syntax, please use the "
                        "option 'snapshot' instead.")

        return host, snapshot
