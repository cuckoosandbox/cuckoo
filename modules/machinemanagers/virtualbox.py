import os
import time
import subprocess

from lib.cuckoo.common.abstracts import Dictionary, MachineManager

class VirtualBox(MachineManager):
    def start(self, label):
        if self.config.getboolean("virtualbox", "headless"):
            subprocess.call(["VBoxHeadless", "-startvm", label], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            subprocess.call(["VBoxManage", "startvm", label], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stop(self, label):
        subprocess.call(["VBoxManage", "controlvm", label, "poweroff"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)
        subprocess.call(["VBoxManage", "snapshot", label, "restorecurrent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
