import os
import time
import subprocess

from lib.cuckoo.common.abstracts import Dictionary, MachineManager

class VirtualBox(MachineManager):
    def start(self, label):
        if self.config.getboolean("virtualbox", "headless"):
            subprocess.call(["VBoxHeadless", "-startvm", label])
        else:
            subprocess.call(["VBoxManage", "startvm", label])

    def stop(self, label):
        subprocess.call(["VBoxManage", "controlvm", label, "poweroff"])
        time.sleep(3)
        subprocess.call(["VBoxManage", "snapshot", label, "restorecurrent"])
