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
        try:
            subprocess.Popen([self.options.virtualbox.path,
                              "startvm",
                              label,
                              "--type",
                              self.options.virtualbox.mode],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed starting the machine in %s mode: %s"
                                     % (mode.upper(), e.message))

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

        time.sleep(3)

        try:
            if subprocess.call([self.options.virtualbox.path, "snapshot", label, "restorecurrent"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error restoring the machine's snapshot")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed restoring the machine: %s" % e.message)

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
