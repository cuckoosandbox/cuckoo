# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import time
import logging
import subprocess
import os.path

# proxmox lib https://github.com/Daemonthread/pyproxmox
from pyproxmox import *

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class Proxmox(MachineManager):
    """Virtualization layer for Proxmox."""

    # VM states.
    RUNNING = "running"
    POWEROFF = "stopped"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if missing option.
        """
        # Proxmox specific checks.
        if not self.options.proxmox.node:
            raise CuckooCriticalError("Proxmox node missing, please add it to the config file")
        if not self.options.proxmox.host:
            raise CuckooCriticalError("Proxmox host missing, please add it to the config file")
        if not self.options.proxmox.username:
            raise CuckooCriticalError("Proxmox username missing, please add it to the config file")
        if not self.options.proxmox.password:
            raise CuckooCriticalError("Proxmox password missing, please add it to the config file")

        for machine in self.machines():
            self._check_snapshot(machine.label)

        # Base checks.
        super(Proxmox, self)._initialize_check()

    def _connect(self):
        """Connect to a proxmox instance
        @raise CuckooCriticalError: if unable to connect
        @return pyproxmox object
        """
        try:
            auth = prox_auth( self.options.proxmox.host, 
                    self.options.proxmox.username,
                    self.options.proxmox.password)
        except pycurl.error as e:
            log.debug(e)
            raise CuckooCriticalError("Can't connect to proxmox host %s" % self.options.proxmox.host)
        except ValueError as e:
            raise CuckooCriticalError("Wrong proxmox username/password")
        
        return pyproxmox(auth)

    def _check_snapshot(self, label):
        """Check snapshot and VMID existance
        @param label: VMID,snapname
        @raise CuckooMachineError: if VMID or snapshot not found.
        """
        vmid, snapshot = self._parse_label(label)
        proxmox = self._connect()

        log.debug("Checking if vm %s and snapshot %s exist" % (vmid, snapshot))

        config = proxmox.getSnapshotConfigVirtualMachine(self.options.proxmox.node, vmid, snapshot)

        if config['data'] == None:
            raise CuckooMachineError("VMID or snapshot not found")
        
        

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name. (label == VMID)
        @raise CuckooMachineError: if unable to start.
        """
        vmid, snapshot = self._parse_label(label)
        proxmox = self._connect()

        log.debug("Starting vm %s with snapshot %s" % (vmid, snapshot))

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError("Trying to start an already started vm %s" % label)

        proxmox.rollbackVirtualMachine(self.options.proxmox.node, vmid, snapshot)
        proxmox.startVirtualMachine(self.options.proxmox.node, vmid) 

        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        vmid, snapshot = self._parse_label(label)
        proxmox = self._connect()

        log.debug("Stopping vm %s" % vmid)
        proxmox.stopVirtualMachine(self.options.proxmox.node, vmid)

        self._wait_status(label, self.POWEROFF)


    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """

        status = None

        vmid, snapshot = self._parse_label(label)
        proxmox = self._connect()
        log.debug("Getting status for %s" % vmid)

        d = proxmox.getVirtualStatus(self.options.proxmox.node, vmid)
        if d['data'] == None:
            raise CuckooMachineError("Unable to get status for %s" % label)
            
        status = d['data']['status']

        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError("Unable to get status for %s" % label)


    def _parse_label(self, label):
        """Parse configuration file label.
        @param label: configuration option from config file
        @return: tuple of host file path and snapshot name
        """
        opts = label.strip().split(",")
        if len(opts) != 2:
            raise CuckooMachineError("Wrong label syntax for %s in proxmox.conf: %s" % label)

        vmid = int(opts[0].strip())
        snapshot = str(opts[1].strip())
        return vmid, snapshot

