import os
import time
import subprocess
import ConfigParser

from lib.cuckoo.common.abstracts import Dictionary, MachineManager

class VirtualBox(MachineManager):
    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.read("conf/virtualbox.conf")
        self.machines = []

    def initialize(self):
        machines_list = self.config.get("VirtualBox", "machines").strip().split(",")
        for machine_id in machines_list:
            machine = Dictionary()
            machine.id = machine_id
            machine.label = self.config.get(machine_id, "label")
            machine.platform = self.config.get(machine_id, "platform")
            machine.ip = self.config.get(machine_id, "ip")
            machine.locked = False
            self.machines.append(machine)

    def acquire(self, label=None, platform=None):
        if label:
            for machine in self.machines:
                if machine.label == label and not machine.locked:
                    machine.locked = True
                    return machine
        elif platform:
            for machine in self.machines:
                if machine.platform == platform and not machine.locked:
                    machine.locked = True
                    return machine
        else:
            for machine in self.machines:
                if not machine.locked:
                    machine.locked = True
                    return machine

        return None

    def release(self, label=None):
        if label:
            for machine in self.machines:
                if machine.label == label:
                    machine.locked = False

    def start(self, label):
        if self.config.getboolean("VirtualBox", "headless"):
            subprocess.call(["VBoxHeadless", "-startvm", label])
        else:
            subprocess.call(["VBoxManage", "startvm", label])

    def stop(self, label):
        subprocess.call(["VBoxManage", "controlvm", label, "poweroff"])
        time.sleep(3)
        subprocess.call(["VBoxManage", "snapshot", label, "restorecurrent"])
