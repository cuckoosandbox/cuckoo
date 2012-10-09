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
    ABORTED = "aborted"
    ERROR = "machete"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        # VirtualBox specific checks.
        if not self.options.virtualbox.path:
            raise CuckooMachineError("VirtualBox VBoxManage path missing, please add it to configuration")
        if not os.path.exists(self.options.virtualbox.path):
            raise CuckooMachineError("VirtualBox VBoxManage not found in specified path %s" % self.options.virtualbox.path)
        if not self.options.virtualbox.timeout:
            raise CuckooMachineError("VirtualBox timeout setting not found, please add it to configuration")
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

        if self._status(label) in [self.POWEROFF, self.ABORTED]:
            log.debug("Trying to stop an already stopped vm %s" % label)
        else:
            try:
                proc = subprocess.Popen([self.options.virtualbox.path, "controlvm", label, "poweroff"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
                # Sometimes VBoxManage stucks when stopping vm so we needed
                # to add a timeout and kill it after that.
                stop_me = 0
                while proc.poll() is None:
                    if stop_me < self.options.virtualbox.timeout:
                        time.sleep(1)
                        stop_me += 1
                    else:
                        log.debug("Stopping vm %s timeouted. Killing" % label)
                        proc.terminate()

                if proc.returncode != 0 and stop_me < self.options.virtualbox.timeout:
                    log.debug("VBoxManage exited with error powering off the machine")
            except OSError as e:
                raise CuckooMachineError("VBoxManage failed powering off the machine: %s" % e)
            self._wait_status(label, [self.POWEROFF, self.ABORTED])

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
                # It's quite common for virtualbox crap utility to exit with:
                # VBoxManage: error: Details: code E_ACCESSDENIED (0x80070005)
                # So we just log to debug this.
                log.debug("VBoxManage returns error checking status for machine %s: %s"
                                       % (label, err))
                return self.ERROR
        except OSError as e:
            log.warning("VBoxManage failed to check status for machine %s: %s"
                                     % (label, e))
            return self.ERROR

        for line in output.split("\n"):
            state = re.match(r"VMState=\"(\w+)\"", line, re.M|re.I)
            if state:
                status = state.group(1)
                log.debug("Machine %s status %s" % (label, status))
                return status.lower()
        raise CuckooMachineError("Unable to get status for %s" % label)

    def _wait_status(self, label, state):
        """Waits for a vm status.
        @param label: virtual machine name.
        @param state: virtual machine status, accepts more than one states in a list.
        @raise CuckooMachineError: if default waiting timeout expire.
        """
        # This block was originally suggested by Loic Jaquemet.
        waitme = 0
        current = self._status(label)
        if isinstance(state, str):
            state = [state]
        while current not in state:
            log.debug("Waiting %i cuckooseconds for vm %s to switch to status %s" % (waitme, label, state))
            if waitme > int(self.options.virtualbox.timeout):
                raise CuckooMachineError("Waiting too much for vm %s status change. Please check manually" % label)
            time.sleep(1)
            waitme += 1
            current = self._status(label)
