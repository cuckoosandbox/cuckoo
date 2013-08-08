# Copyright (C) 2013 Dennis Giese [dennis.giese@t-systems.com].
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import subprocess
import os.path
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class Esxi(MachineManager):
    """Virtualization layer for VMware ESXi/vCenter (via vmware-vsphere-cli)."""

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if something is missing or wrong.
        """  

        # Check if vmware-vsphere-cli is installed
        if not self.options.esxi.path:
            raise CuckooMachineError("path to vmware-cmd is missing, please add it to esxi.conf")
        if not os.path.exists(self.options.esxi.path):
            raise CuckooMachineError("vmware-cmd not found, check if vmware-vsphere-cli is installed")
        # Check VM-files
        for machine in self.machines():
            host = machine.label
            self._check_vmx(host)
        # Base checks
        super(Esxi, self)._initialize_check()

    def _check_vmx(self, host):
        """Checks a vmx file
        @param host: file path
        @raise CuckooMachineError: check if path valid
        """

        if not host.endswith(".vmx"):
            raise CuckooMachineError("Wrong configuration: vm path not ending with .vmx: %s" % host)

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine identifier: path to vmx file
        @raise CuckooMachineError: if unable to start.
        """
        host = label

        # Check if Sandbox is already running
        if self._is_running(host):
            raise CuckooMachineError("Machine %s is already running" % host)

        # Start Sandbox by reverting the last snapshot of the running machine
        log.debug("Starting vm %s" % host)
        try:
                subprocess.call("%s -H %s --username %s --password %s %s revertsnapshot" % (self.options.esxi.path, self.options.esxi.esxihost, self.options.esxi.user, self.options.esxi.password, host),
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        except OSError as e:
            raise CuckooMachineError("Unable to start machine %s: %s"
                                     % (host, e))

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine identifier: path to vmx file.
        @raise CuckooMachineError: if unable to stop.
        """
        host = label

        # Stop Virtual Machine (hard shutdown because we dont care about the vm [next time we recover snapshot anyway])
        log.debug("Stopping vm %s" % host)
        if self._is_running(host):
            try:
                subprocess.call("%s -H %s --username %s --password %s %s stop hard" % (self.options.esxi.path, self.options.esxi.esxihost, self.options.esxi.user, self.options.esxi.password, host),
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            except OSError as e:
                raise CuckooMachineError("Error shutting down machine %s: %s" % (host, e))
        else:
            log.warning("Trying to stop an already stopped machine: %s" % host)

    def _is_running(self, host):
        """Checks if host is running.
        @param host: file path
        @return: running status
        """

        try:
            output, error = subprocess.Popen("%s -H %s --username %s --password %s %s getstate" % (self.options.esxi.path, self.options.esxi.esxihost, self.options.esxi.user, self.options.esxi.password, host),
                              shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE).communicate()
            if output:
                if "on" in output:
                    return True
                else:
                    return False
            else:
                raise CuckooMachineError("Unable to check running status for %s. No output from `vmware-cmd getstate`" % host)
        except OSError as e:
            raise CuckooMachineError("Unable to check running status for %s. Error: %s" % (host, e))

