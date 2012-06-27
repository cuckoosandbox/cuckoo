# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import logging
import subprocess

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VirtualBox(MachineManager):
    """Virtualization layer forVirtualBox."""

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        if self.config.getboolean("virtualbox", "headless"):
            try:
                subprocess.Popen(["VBoxHeadless", "-startvm", label],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            except OSError as e:
                raise CuckooMachineError("VBoxHeadless failed starting the machine in headless mode: %s" % e.message)
        else:
            try:
                subprocess.Popen(["VBoxManage", "startvm", label],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            except OSError as e:
                raise CuckooMachineError("VBoxManage failed starting the machine in GUI mode: %s" % e.message)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        try:
            if subprocess.call(["VBoxManage", "controlvm", label, "poweroff"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error powering off the machine")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed powering off the machine: %s" % e.message)

        time.sleep(3)

        try:
            if subprocess.call(["VBoxManage", "snapshot", label, "restorecurrent"],
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
            proc = subprocess.Popen(["VBoxManage", "list", "vms"],
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
