# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import re
import os
import time
import logging
import subprocess

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class VirtualBox(MachineManager):
    """Virtualization layer forVirtualBox."""
    def initialize(self, *args):
        '''
        Call the abstract classes initialize function and then
        attempt to enumerate the ip address assign to the host
        using the VirualBox management console.
        '''
        super(VirtualBox, self).initialize(*args)
        ip_add_re = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        # example IPv4 propert
        # Name: /VirtualBox/GuestInfo/Net/.*/V4/IP,.*
        ip_prop = re.compile(r"/VirtualBox/GuestInfo/Net/[0-9]+/V4/IP")
        get_ip = lambda props: [ip_add_re.findall(prop)[0] for prop in props.splitlines() \
                                if len(ip_prop.findall(prop))  > 0 ]
        # lets actually get the ip address of the machine
        for machine in self.machines:
            try:
                proc  = subprocess.Popen(["VBoxManage", "guestproperty", 'enumerate', machine.label],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
                props = proc.stdout.read()
                ips = get_ip(props)
                if len(ips) > 0 and (machine.ip is None or machine.ip == ''):
                    past_ip = machine.ip
                    machine.ip = ips[0]
                    log.info(u"%s IP was missing, so it was set to: %s"%(machine.label, ips[0]))
                elif not machine.ip in ips:
                    log.warning(u'Potential misconfiguration: %s\'s IP configured as: %s, but these are the IPs found: (%s)'%\
                           (machine.label, machine.ip, ", ".join(ips)))

            except OSError:
                raise CuckooMachineError("VBoxManage OS error starting vm or file not found")
        
        
    
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
