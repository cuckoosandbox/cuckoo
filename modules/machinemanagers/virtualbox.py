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
                if subprocess.call(["VBoxHeadless", "-startvm", label],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE):
                    raise CuckooMachineError("VBoxHeadless exited with error starting vm")
            except OSError:
                raise CuckooMachineError("VBoxHeadless OS error starting vm or file not found")
        else:
            try:
                if subprocess.call(["VBoxManage", "startvm", label],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE):
                    raise CuckooMachineError("VBoxManage exited with error starting vm")
            except OSError:
                raise CuckooMachineError("VBoxManage OS error starting vm or file not found")

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        try:
            if subprocess.call(["VBoxManage", "controlvm", label, "poweroff"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error powering off vm")
        except OSError:
            raise CuckooMachineError("VBoxManage OS error powering off vm or file not found")

        time.sleep(3)

        try:
            if subprocess.call(["VBoxManage", "snapshot", label, "restorecurrent"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE):
                raise CuckooMachineError("VBoxManage exited with error restoring vm's snapshot")
        except OSError:
            raise CuckooMachineError("VBoxManage OS error restoring vm's snapshot or file not found")

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        try:
            proc = subprocess.Popen(["VBoxManage", "list", "vms"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output = proc.communicate()
        except OSError:
            raise CuckooMachineError("VBoxManage error listing installed VMs")

        machines = []
        for line in output[0].split("\n"):
            try:
                label = line.split('"')[1]
                if label == "<inaccessible>":
                    log.warning("Found an inacessible vitual machine. Please check his state")
                else:
                    machines.append(label)
            except IndexError:
                continue
        return machines
