# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VirtualBox(MachineManager):
    """Virtualization layer forVirtualBox."""
    SAVED = 'saved'
    RUNNING = 'running'
    POWEROFF = 'poweroff'
    
    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        # VirtualBox specific checks.
        if not self.options.virtualbox.path:
            raise CuckooMachineError("VirtualBox VBoxManage path missing, please add it to configuration")
        if not os.path.exists(self.options.virtualbox.path):
            raise CuckooMachineError("VirtualBox VBoxManage not found in specified path %s" % self.options.virtualbox.path)
        # Base checks.
        super(VirtualBox, self)._initialize_check()

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        self.wait_for(label, self.SAVED)

        try:
            if subprocess.call([self.options.virtualbox.path,
                              "startvm",
                              label,
                              "--type",
                              self.options.virtualbox.mode],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE):
                raise CuckooMachineError('VBoxManage failed starting with error %d - %s'%(proc.returncode, out))
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed starting the machine in %s mode: %s"
                                     % (mode.upper(), e.message))

        self.wait_for(label, self.RUNNING)
        return

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        try:
            if subprocess.call([self.options.virtualbox.path, "controlvm", label, "poweroff"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error powering off the machine")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed powering off the machine: %s" % e.message)

        self.wait_for(label, self.POWEROFF)

        try:
            if subprocess.call([self.options.virtualbox.path, "snapshot", label, "restorecurrent"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error restoring the machine's snapshot")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed restoring the machine: %s" % e.message)

        self.wait_for(label, self.SAVED)
        return

    def memdump(self, label, filename):
        """memdump a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        ##return # DEBUG
        log.debug('memdump for %s at %s'%(label, filename))
        try:
            self.wait_for(label, self.RUNNING)

            log.debug('Starting the memdump for %s at %s'%(label, filename))
            if subprocess.call([self.options.virtualbox.path,
                              "debugvm",
                              label,
                              "dumpguestcore",
                              "--filename",
                              filename],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage failed memdump-ing the machine")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed memdump-ing the machine in %s mode: %s"
                                     % (mode.upper(), e.message))
        return
        
    def wait_for(self, label, state):
        i = 0
        while state != self._check(label):
          log.debug('Waiting for VM %s to switch to status %s'%(label, state))
          if i > 15: # TODO self.options.virtualbox.timeout:
            log.warning('waiting VM %s to come online from %s to %s '%(label, self._check(label), state))
          if i > 30: # TODO self.options.virtualbox.timeout:
            raise CuckooMachineError("VBoxManage failed to put the VM in running state")
          time.sleep(1)
          i+=1
        return
        
    def _check(self, label):
        ''' states: running, saved '''
        log.debug('Check VM to come online for %s '%(label))
        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                              "showvminfo",
                              label,
                              "--machinereadable"],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if proc.returncode != 0:
              raise CuckooMachineError("VBoxManage failed to check vm status ret: %d err: %s"
                                     % (proc.returncode, err))            
            status = [line for line in out.split('\n') if 'VMState=' in line][0]
            status = status.split('="')[1].rstrip('"')
            log.debug('VMStatus is %s'%(status))
            return status
        except Exception as e:
            log.error(e,message)
            raise CuckooMachineError("VBoxManage failed echking-ing the machine in %s mode: %s"
                                     % (mode.upper(), e.message))    

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        try:
            proc = subprocess.Popen([self.options.virtualbox.path, "list", "vms"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output = proc.communicate()
        except OSError as e:
            raise CuckooMachineError("VBoxManage error listing installed machines: %s" % e.message)

        machines = []
        for line in output[0].split("\n"):
            try:
                label = line.split('"')[1]
                if label == "<inaccessible>":
                    log.warning("Found an inaccessible vitual machine: please check his state")
                else:
                    machines.append(label)
            except IndexError:
                continue

        return machines
