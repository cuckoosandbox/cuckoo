# Copyright (C) 2012 Mike Tu (@mt00at)
#
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

import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VMware(MachineManager):
    """Virtualization layer for VMware Workstation using vmrun utility."""

    def _initialize_check(self):
        """Check for vmrun when a machine manager is initialized.
        @raise CuckooMachineError: if vmrun is not found.
        """  
        if not self.options.vmware.path:
            raise CuckooMachineError("VMware vmrun path missing, please add it to vmware.conf")
        if not os.path.exists(self.options.vmware.path):
            raise CuckooMachineError("VMware vmrun not found in specified path %s" % self.options.vmware.path)

    def start(self, label):
        """Start a virtual machine.
        @param label: path_to_vmx_file,current_snapshot
        @raise CuckooMachineError: if unable to start.
        """
        vmx_snap = self.get_vmx_snap(label)
        try:
            output,error = subprocess.Popen([self.options.vmware.path,
                              "start",
                             vmx_snap[0],
                             self.options.vmware.mode],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE).communicate()
            if output != "":
                log.error("vmrun failed starting the machine: %s" % output)
                raise CuckooMachineError ("vmrun failed starting the machine")
        except OSError as e:
            raise CuckooMachineError("vmrun failed starting the machine in %s mode: %s"
                                     % (self.options.vmware.mode.upper(), e))

    def stop(self, label):
        """Stops a virtual machine.
        @param label: path_to_vmx_file,current_snapshot
        @raise CuckooMachineError: if unable to stop.
        """
        vmx_snap = self.get_vmx_snap(label)
        try:
            if subprocess.call([self.options.vmware.path, 
                               "stop", 
                               vmx_snap[0]],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("vmrun exited with error powering off the machine")
        except OSError as e:
            raise CuckooMachineError("vmrun failed powering off the machine: %s" % e)
        
        time.sleep(3)
        
        try:
            if subprocess.call([self.options.vmware.path, 
                               "revertToSnapshot",
                               vmx_snap[0],
                               vmx_snap[1]],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("vmrun exited with error restoring the machine's snapshot")
        except OSError as e:
            raise CuckooMachineError("vmrun failed restoring the machine: %s" % e)
        
    def get_vmx_snap(self, label):
        """Check label in vmware.conf.
        @param vmx_snap: [path_to_vmx_file, current_snapshot]
        @raise CuckooMachineError: if label format unexpected.
        expected: label = path_to_vmx_file,current_snapshot
        """
        vmx_snap = []
        if not "vmx," in label:
            raise CuckooMachineError("Please check vmx and snapshot in vmware.conf: %s" % label)
        else:
            vmx_snap = label.strip().split(",")
            if len(vmx_snap) != 2:
                raise CuckooMachineError("Please check vmx and snapshot in vmware.conf: %s" % label)
        return vmx_snap        
    
    def _list(self):
        return None

