import os
import subprocess
import ConfigParser

from lib.cuckoo.abstract.machinemanager import MachineManager

class VirtualBox(MachineManager):
    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.read("conf/virtualbox.conf")
        self.machines = []

    def initialize(self):
        machines_list = self.config.get("VirtualBox", "machines").strip().split(",")
        for machine_id in machines_list:
            machine = {"id"       : machine_id,
                       "label"    : self.config.get(machine_id, "label"),
                       "platform" : self.config.get(machine_id, "platform"),
                       "username" : self.config.get(machine_id, "username"),
                       "password" : self.config.get(machine_id, "password"),
                       "ip"       : self.config.get(machine_id, "ip"),
                       "locked"   : False}
            self.machines.append(machine)

    def acquire(self, label=None, platform=None):
        if label:
            for machine in self.machines:
                if machine["label"] == label and not machine["locked"]:
                    machine["locked"] = True
                    return machine
        elif platform:
            for machine in self.machines:
                if machine["platform"] == platform and not machine["locked"]:
                    machine["locked"] = True
                    return machine
        else:
            for machine in self.machines:
                if not machine["locked"]:
                    machine["locked"] = True
                    return machine

        return None

    def start(self, label):
        if self.config.getboolean("VirtualBox", "headless"):
            subprocess.call(["VBoxHeadless", "-startvm", label])
        else:
            subprocess.call(["VBoxManage", "startvm", label])

    def stop(self, label):
        subprocess.call(["VBoxManage", "controlvm", label, "poweroff"])
        subprocess.call(["VBoxManage", "snapshot", label, "restorecurrent"])
