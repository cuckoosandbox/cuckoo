### ESXi over SSH Connector module
### (c) Jakub Sucharkiewicz
### 
### for using the VmWare ESXi Server 
### with the free License
### (w/o the vSpere API)


import logging
import os
import subprocess
import time

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import (
    CuckooCriticalError, CuckooMachineError, CuckooMachineSnapshotError,
    CuckooMissingMachineError
)
from cuckoo.misc import Popen

log = logging.getLogger(__name__)

class esxOssh(Machinery):
    """Virtualization layer for ESXi over ssh commands."""
    
    LABEL = "label"
    # VM states.
    SAVED = "saved"
    RUNNING = "Powered on"
    POWEROFF = "Powered off"
    ABORTED = "aborted"
    ERROR = "machete"

    def _initialize_check(self):

	if not self.options.esxOssh.host:
            raise CuckooCriticalError(
                "ESXi Host not found or configured"
                "Name: %s" %
                self.options.esxOssh.host
            )

	if not self.options.esxOssh.vmgroup:
            raise CuckooCriticalError(
                "ESXi VMgroup of Zombies not found or configured"
                "Name: %s" %
                self.options.esxOssh.vmgroup
            )

	if not self.options.esxOssh.username:
            raise CuckooCriticalError(
                "ESXi Username not found or configured"
                "Name: %s" %
                self.options.esxOssh.username
            )
	
	if not self.options.esxOssh.password:
            raise CuckooCriticalError(
                "ESXi password not found or configured"
                "Name: %s" %
                self.options.esxOssh.password
            )

        super(esxOssh, self)._initialize_check()

        # Restore each virtual machine to its snapshot. This will crash early
        # for users that don't have proper snapshots in-place, which is good.
        # TODO This should be ported to all machinery engines.
        machines = self._list()

    def _list(self):

        """Lists virtual machines installed.
        @return: virtual machine names list.
        """

        """Get all the VMID's and Label out of the ESXi"""
      
        try:
            args = [
                "sshpass", "-p", self.options.esxOssh.password, "ssh", self.options.esxOssh.username + "@" + self.options.esxOssh.host, "vim-cmd", "vmsvc/getallvms", "|", "grep", self.options.esxOssh.vmgroup,
            ]
            output, _ = Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True
            ).communicate()
        except OSError as e:
            raise CuckooMachineError(
                "ESXi error listing installed machines: %s" % e
            )

        machines = []
        for line in output.split("\n"):
            mach = line.split()
            if not mach:
                continue

	    machines.append(mach[1])

        return machines


    def restore(self, label, machine):
        
        """Restore a VM to its snapshot."""
        machine = self.db.view_machine_by_label(label)
        args = [
                "sshpass", "-p", self.options.esxOssh.password, "ssh", self.options.esxOssh.username + "@" + self.options.esxOssh.host, "vim-cmd", "vmsvc/snapshot.revert", machine.vmid, machine.snapid, "0"
        ]
        try:
            p = Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True
            )
            _, err = p.communicate()
            if p.returncode:
                raise OSError("error code %d: %s" % (p.returncode, err))
        except OSError as e:
            raise CuckooMachineSnapshotError(
                "ESXi failed trying to restore the snapshot of "
                "machine '%s' (this most likely means there is no snapshot, "
                "please refer to our documentation for more information on "
                "how to setup a snapshot for your VM): %s" % (label, e)
            )

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s", label)

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError(
                "Trying to start an already started VM: %s" % label
            )

        machine = self.db.view_machine_by_label(label)
        self.restore(label, machine)

        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        machine = self.db.view_machine_by_label(label)
        status = self._status(label)

        if status == self.SAVED:
            return

        if status == self.POWEROFF or status == self.ABORTED:
            raise CuckooMachineError(
                "Trying to stop an already stopped VM: %s" % label
            )
        try:
            args = [
                 "sshpass", "-p", self.options.esxOssh.password, "ssh", self.options.esxOssh.username + "@" + self.options.esxOssh.host, "vim-cmd", "vmsvc/power\.off", machine.vmid,
            ]
            proc = Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True
            )
            if proc.returncode != 0:
                log.debug(
                    "ESXi exited with error powering off the machine"
                )
        except OSError as e:
            raise CuckooMachineError(
                "ESXi failed powering off the machine: %s" % e
            )

        self._wait_status(label, self.POWEROFF, self.ABORTED, self.RUNNING)

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        status = self.vminfo(label, "VMState")
        if status is False:
            status = self.ERROR

        # Report back status.
        if status:
            self.set_status(label, status)
            return status

        raise CuckooMachineError(
            "Unable to get status for %s" % label
        )

    def vminfo(self, label, field):
        """Returns False if invoking ESXi fails. Otherwise the VM
        information value, if any."""
	machine = self.db.view_machine_by_label(label)
	statVM = ""
	stat = ""


        try:
            args = [
		"sshpass", "-p", self.options.esxOssh.password, "ssh", self.options.esxOssh.username + "@" + self.options.esxOssh.host, "vim-cmd", "vmsvc/power\.getstate", machine.vmid,
            ]
            output, _ = Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True
            ).communicate()
        except OSError as e:
            raise CuckooMachineError(
                "ESXi error listing installed machines: %s" % e
            )
	statVM = output.split('\n')
	log.debug("MachineVMID: '%s' in State: '%s'", machine.vmid, statVM[1].strip())
	stat = statVM[1].strip()
	    
	return stat
