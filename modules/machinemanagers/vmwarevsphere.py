# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import re
import os
import time
import logging
import subprocess

import psphere
from psphere.managedobjects import HostSystem, ResourcePool
from psphere.client import Client
from psphere.managedobjects import VirtualMachine

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class VMWareMachine(object):
    DEFAULT_SNAPSHOT = "Cuckoo" 
    def __init__(self, machine, client, host, mor):
        '''
        Initialize the VM container with the pvsphere client, host, and a vm managed object reference
        the machine is the MachineManager abstract machine, which contains only the IP
        '''
        self.vm_name = vm.name
        self.ip = machine.ip
        self.snapshots = {}
        self.initialize(client, host, mor)
    

    def is_vmtools_installed(self):
        '''
        See if vmware tools is installed in  the host.
        '''
       
       return self.mor.guest.toolsRunningStatus == "guestToolsRunning"

    
    def initialize(self, client, host, vm):
        '''
        Initialize this vm containers connection to the vsphere server, the host system mor, the vm mor, and the
        valid snapshots for the guest.  If the guest has no snapshots one is created automatically.
        '''
        self.client = client
        self.host = host
        self.mor = vm
        self.attempt_ip_update():
        snapshots = []

        try:
            snapshots = self.mor.snapshot.rootSnapshotList

        except AttributeError:
            logger.warn("No snapshot for %s, so %s is being created as a base line."%(vm.name,DEFAULT_SNAPSHOT )
            task = vm.CreateSnapshot_Task(**{'name':DEFAULT_SNAPSHOT, "description":"Cuckoo Snapshot", "memory":False, 'quiesce':False})
            self.wait_for_task(task, 5)
            self.mor.update()
            self.snapshots = self.mor.snapshot.rootSnapshotList
        
        for s in snapshots:
            self.snapshots[s.name] = s
        
        
        
        
    
    def wait_for_task(self, task, timeout=2.0):
        '''
        @param task: task data object that represents a queued or running task
                     in vsphere.
        @param timeout: (default 2.0) time in seconds to wait before timing out
        @raise CuckooMachineError: if a timeout occurs
        
        Wait for a task to complete running or timeout.  Crude implementation.  
        #TODO use alarms to perform asynchronous start-up and shutdowns 
        
        '''
        is_running = False
        while task.info.state in ["queued", "running"]:
            if not task.info.state == "running":
                logger.debug("waiting 5 seconds for the vm task to run")
                time.sleep(timeout)
            elif not is_running and task.info.state == "running":
                logger.debug("waiting 5 seconds for the vm task to complete")
                is_running = True 
                task.update()
                if task.info.state != "running":
                    break
                time.sleep(timeout)
            else:
                task.update()
                logger.debug("task has not completed yet, something may be wrong")
                raise  CuckooMachineError("vSphere timed pout performing task:\n %s"%(task.info))
            task.update()
            
    def get_ipaddr(self):
        '''
        Attempt to update to get the ip address of the vm.  If vmware tools are installed,
        query the host, if not, then use the one in the config file.

        @raise CuckooMachineError: if an ip address can not be determined
        '''
        self.mor.update()
        if self.is_vmtools_installed():
           return self.mor.guest.ipAddress:w
        
        if not self.ip is None and self.ip != "":
           return self.ip
        
        raise  CuckooMachineError("VM Name: (%s) is not running vmware tools and an ip has not been assigned."%self.vm_name)

    def attempt_ip_update(self):
        '''
        Attempt to update to get the ip address of the vm.  If vmware tools are installed,
        query the host, if not, then use the one in the config file.

        '''
        # maybe the ip address is already set in the host
        try:
            self.ip = self.get_ipaddr()
            logger.debug("Successfully updated %s's IP Address: %s"%(self.vm_name, self.ip))
            return True
        except:
            pass
        logger.debug("Failed to updated %s's IP Address: %s"%(self.vm_name, self.ip))
        return False

    def start(self):
        '''
        Attempt to start a the guest and the determine the ip address
        @raise CuckooMachineError: if an ip address can not be determined or guest does not start

        '''
        self.host.update()
        kargs = {'host':self.host}
        task = None
        vm = self.mor.update()
        try:
            task = vm.PowerOn_Task(**kargs)
        except Vim, e:
            raise  CuckooMachineError("vSphere failed to power on %s:\n\tError: %s"%\
                 (vm.name, e))
        self.wait_for_task(task)
        time.sleep(3.0)
        #TODO fix this, the ip_update should occur once the host has completed startup
        self.attempt_ip_update()
        
        

    def stop(self):
        '''
        Attempt to stop a the guest and the determine the ip address
        @raise CuckooMachineError: if guest does not stop or some other fault occurs or a 
        timeout occurs
 
        '''
        self.host.update()
        kargs = {'host':self.host}
        task = None
        vm = self.mor.update()
        try:
            task = vm.PowerOff_Task(**kargs)
        except Vim, e:
            raise  CuckooMachineError("vSphere failed to create a snapshot for %s:\n\tError: %s"%\
                 (vm.name, e))
        self.wait_for_task(task)
    
    def create_snapshot(self, name="Cuckoo", desc="Cuckoo Default", memory=False, quiesce=False):
        '''
        Create a guest snapshot
        @param name: (default: Cuckoo) name of the snapshot
        @param desc: (default: Cuckoo Default) description of the snapshot
        @param memory: (default: False) see vSphere SDK Docs CreateSnapshot_Task
        @param quiesce: (default: False) see vSphere SDK Docs CreateSnapshot_Task
        @raise CuckooMachineError: if a vim fault occurs or a timeout occurs

        '''
        kargs = {'name':name, 'description':desc, 'memory':memory, 'quiesce':quiesce}
        task = None
        try:
            self.mor.update()
            task = self.mor.CreateSnapshot_Task(**kargs)
        except Vim, e:
            raise  CuckooMachineError("vSphere failed to create a snapshot for %s:\n\tError: %s"%\
                 (self.vm_name, e))
        self.wait_for_task(task)
    

    def revert_to_snapshot(self, snapshot_name="current", suppressPowerOn=True, powerOn=True):
        '''
        Revert to aa guest snapshot
        @param snapshot_name: (default: current) name of the snapshot to revert to
        @param suppressPowerOn: (default: True)revert to snapshot in the off state
        @param powerOn: (default: True) turn machine on after reverting the snapshot 
        @raise CuckooMachineError: if a vim fault occurs or a timeout occurs or the snapshot name does not exist
        '''
        task = None
        kargs = {'host':self.host, 'suppressPowerOn':True}
        
        if not snapshot_name.lower() is 'current' and \
           not snapshot_name in self.snapshots:
            raise  CuckooMachineError("VM Name: (%s) is not valid."%self.vm_name)
        
        vm = self.mor
        vm.update()
        kargs = {'name':name, 'description':desc, 'memory':memory, 'quiesce':quiesce}
        try:
            if snapshot_name.lower() == "current":
                task = vm.RevertToCurrentSnapshot_Task(**kargs)
            else:
                snapshot = self.snapshots[snapshot_name]
                snapshot.update()
                task = snapshot.RevertToSnapshot_Task(**kargs)
        except Vim, e:
            raise  CuckooMachineError("vSphere failed to revert vm (%s) to snapshot (%s) for %s:\n\tError: %s"%\
                 (self.vm_name, snapshot_name, e))
        
        self.wait_for_task(task)
        
        if powerOn and vm.guest.guestState != "running":
            self.start()
        

        
         

class VMwareVshpere(MachineManager):
    """Virtualization layer forVirtualBox."""
    def initialize(self,  *args):
        '''
        Call the abstract classes initialize function and then
        attempt to enumerate the ip address assign to the host
        using the VirualBox management console.
        '''
        super(VMwareVshpere, self).initialize(*args)        
        self.vms = {}
        self.host = self.config.get("vsphere", "host")
        self.user = self.config.get("vsphere", "user")
        self.password = self.config.get("vsphere", "password")
        self.client = Client(self.host, self.user, self.password)
        
        hosts = HostSystem.all(self.client)
        self.host = hosts[0]
        self.vms = Dictionary()
        
        machines = {}
        for i in self.machines:
            machines[i.label] = i
        
        for vm in VirtualMachine.all(client):
            if not vm.name in machines:
                continue
            machine = VMWareMachine(machine[i], self.client, self.host, vm)
            self.vms[machine.label] = machine
        

    def revert(self, label, snapshot='current'):
        """Revert a virtual machine to the specified snapshot and restart it.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        if not label in self.vms:
            CuckooMachineError("%s is not a valid vm."%label)
        vm = self.vms[label]
        vm.revert_to_snapshot(snapshot)            

        
                
    
    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        if not label in self.vms:
            raise CuckooMachineError("%s is not a valid VM."%label)
        vm = self.vms[label]
        vm.start()

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        if not label in self.vms:
            raise CuckooMachineError("%s is not a valid VM."%label)
        vm = self.vms[label]
        vm.stop()


    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        host = self.config.get("vsphere", "host")
        user = self.config.get("vsphere", "user")
        password = self.config.get("vsphere", "password")
        client = Client(host, user, password)
        vms = VirtualMachine.all(client)
        l = [vm.name for vm in vms]
        client.logout()
        return l


