import os
import time
import subprocess

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

class VirtualBox(MachineManager):
    def start(self, label):
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
                raise CuckooMachineError("VBoxManage exited with error restoging vm's snapshot")
        except OSError:
            raise CuckooMachineError("VBoxManage OS error restoring vm's snapshot or file not found")