# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class VirtualBox(MachineManager):
    """Virtualization layer for VirtualBox."""

    # VM states.
    SAVED = "saved"
    RUNNING = "running"
    POWEROFF = "poweroff"

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
        log.debug("Starting vm %s" % label)

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError("Trying to start an already started vm %s" % label)

        try:
            if subprocess.call([self.options.virtualbox.path, "snapshot", label, "restorecurrent"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error restoring the machine's snapshot")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed restoring the machine: %s" % e)
        self._wait_status(label, self.SAVED)

        try:
            subprocess.call([self.options.virtualbox.path,
                              "startvm",
                              label,
                              "--type",
                              self.options.virtualbox.mode],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed starting the machine in %s mode: %s"
                                     % (mode.upper(), e))
        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)
        try:
            if subprocess.call([self.options.virtualbox.path, "controlvm", label, "poweroff"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error powering off the machine")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed powering off the machine: %s" % e)
        self._wait_status(label, self.POWEROFF)

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
            raise CuckooMachineError("VBoxManage error listing installed machines: %s" % e)

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

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        @raise CuckooMachineError: if unable to enumerate status.
        """
        log.debug("Getting status for %s"% label)
        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "showvminfo",
                                     label,
                                     "--machinereadable"],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            output, err = proc.communicate()

            if proc.returncode != 0:
              raise CuckooMachineError("VBoxManage returns error checking status for machine %s: %s"
                                       % (label, err))
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed to check status for machine %s: %s"
                                     % (label, e))

        for line in output.split("\n"):
            state = re.match(r"VMState=\"(\w+)\"", line, re.M|re.I)
            if state:
                status = state.group(1)
                log.debug("Machine %s status %s" % (label, status))
                return status
        raise CuckooMachineError("Unable to get status for %s" % label)

    def _wait_status(self, label, state):
        """Waits for a vm status.
        @param label: virtual machine name.
        @param state: virutal machine status.
        @raise CuckooMachineError: if default waiting timeout expire.
        """
        waitme = 0
        while state != self._status(label):
            log.debug("Waiting %i cuckooseconds for vm %s to switch to status %s" % (waitme, label, state))
            if waitme > int(self.options.virtualbox.timeout):
                self.stop(label)
                raise CuckooMachineError("Waiting too much for vm %s status change. Stopping vm and aborting" % label)
            time.sleep(1)
            waitme += 1
