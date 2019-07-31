# Copyright (C) 2017 Menlo Security
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import time

from proxmoxer import ProxmoxAPI, ResourceException

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooMachineError

# silence overly verbose INFO level logging default of proxmoxer module
logging.getLogger("proxmoxer").setLevel(logging.WARNING)

log = logging.getLogger(__name__)

class Proxmox(Machinery):
    """Manage Proxmox sandboxes."""
    def __init__(self):
        super(Proxmox, self).__init__()
        self.node = None
        self.vm = None
        self.timeout = config("cuckoo:timeouts:vm_state")

    def _initialize_check(self):
        """Ensures that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided
        """
        if not self.options.proxmox.username or not self.options.proxmox.password:
            raise CuckooCriticalError(
                "Proxmox credentials are missing, please add them to "
                "the Proxmox machinery configuration file."
            )
        if not self.options.proxmox.hostname:
            raise CuckooCriticalError("Proxmox hostname not set")

        super(Proxmox, self)._initialize_check()

    def find_vm(self, label):
        """Find a VM in the Proxmox cluster and remember its node and vm proxy
        objects for extraction of additional data by other methods.

        @param label: the label of the VM to be compared to the VM's name in
                      Proxmox.
        @raise CuckooMachineError: if the VM cannot be found."""
        proxmox = ProxmoxAPI(self.options.proxmox.hostname,
                             user=self.options.proxmox.username,
                             password=self.options.proxmox.password,
                             verify_ssl=False)

        # /cluster/resources[type=vm] will give us all VMs no matter which node
        # they reside on
        try:
            vms = proxmox.cluster.resources.get(type="vm")
        except ResourceException as e:
            raise CuckooMachineError("Error enumerating VMs: %s" % e)

        for vm in vms:
            if vm["name"] == label:
                # dynamically address
                # /nodes/<node>/{qemu,lxc,openvz,...}/<vmid> to get handle on
                # VM
                node = proxmox.nodes(vm["node"])
                hv = node.__getattr__(vm["type"])
                vm = hv.__getattr__(str(vm["vmid"]))

                # remember various request proxies for subsequent actions
                self.node = node
                self.vm = vm
                return

        raise CuckooMachineError("Not found")

    def wait_for_task(self, taskid):
        """Wait for long-running Proxmox task to finish.

        Only to be called after successfully having called find_vm() or having
        otherwise initialised the Proxmox node object to work against.

        @param taskid: id of Proxmox task to wait for
        @raise CuckooMachineError: if task status cannot be determined."""
        if not self.node:
            raise CuckcooMachineError(
                "BUG: Target Proxmox node not initialized.")

        elapsed = 0
        while elapsed < self.timeout:
            try:
                task = self.node.tasks(taskid).status.get()
            except ResourceException as e:
                raise CuckooMachineError("Error getting status of task "
                                         "%s: %s" % (taskid, e))

            if task["status"] == "stopped":
                return task

            log.debug("Waiting for task %s to finish: %s", taskid, task)
            time.sleep(1)
            elapsed += 1

        return None

    def find_snapshot(self, label):
        """Find a specific or the most current snapshot of a VM.

        Only to be called after successfully having called find_vm() or having
        otherwise initialised the VM object to work against.

        @param label: VM label for additional parameter retrieval
        @raise CuckooMachineError: if snapshots cannot be enumerated."""
        # use a statically configured snapshot name if configured without any
        # additional checks. User has to make sure it exists then.
        snapshot = self.db.view_machine_by_label(label).snapshot
        if snapshot:
            return snapshot

        if not self.vm:
            raise CuckcooMachineError("BUG: Target VM not initialized.")

        # heuristically determine the most recent snapshot if no snapshot name
        # is explicitly configured.
        log.debug("No snapshot configured for VM %s, determining most recent "
                  "one", label)
        try:
            snapshots = self.vm.snapshot.get()
        except ResourceException as e:
            raise CuckooMachineError("Error enumerating snapshots: %s" % e)

        snaptime = 0
        snapshot = None
        for snap in snapshots:
            # ignore "meta-snapshot" current which is the current state
            if snap["name"] == "current":
                continue

            if snap["snaptime"] > snaptime:
                snaptime = snap["snaptime"]
                snapshot = snap["name"]

        return snapshot

    def rollback(self, label):
        """Roll back a VM's status to a statically configured or the most recent
        snapshot.

        @param label: VM label for lookup in Proxmox and additional parameter
                      retrieval.
        @raise CuckooMachineError: if snapshot cannot be found, reverting the
                                   machine to the snapshot cannot be triggered
                                   or times out or fails for another reason."""

        snapshot = self.find_snapshot(label)
        if not snapshot:
            raise CuckooMachineError("No snapshot found - check config")

        try:
            log.debug("Reverting VM %s to snapshot %s", label, snapshot)
            taskid = self.vm.snapshot(snapshot).rollback.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger rollback to "
                                     "snapshot %s: %s" % (snapshot, e))

        task = self.wait_for_task(taskid)
        if not task:
            raise CuckooMachineError("Timeout expired while rolling back to "
                                     "snapshot %s" % snapshot)
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Rollback to snapshot %s failed: %s"
                                     % (snapshot, task["exitstatus"]))

    def start(self, label, task):
        """Roll back VM to known-pristine snapshot and optionally start it if
        not already running after reverting to the snapshot.

        @param label: VM label for lookup by name in Proxmox additional
                      parameter retrieval.
        @raise CuckooMachineError: if snapshot cannot be found, reverting the
                                   machine to the snapshot or starting the VM
                                   cannot be triggered or times out or fails
                                   for another reason."""
        self.find_vm(label)
        self.rollback(label)

        try:
            status = self.vm.status.current.get()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't get status: %s" % e)

        if status["status"] == "running":
            log.debug("VM already running after rollback, no need to start it")
            return

        try:
            log.debug("Starting VM %s", label)
            taskid = self.vm.status.start.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger start: %s" % e)

        task = self.wait_for_task(taskid)
        if not task:
            raise CuckooMachineError("Timeout expired while starting")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Start failed: %s" % task["exitstatus"])

    def stop(self, label):
        """Do a hard shutdown of the VM.

        @param label: VM label for lookup by name in Proxmox.
        @raise CuckooMachineError: if VM cannot be found or stopping it cannot
                                   be triggered or times out or fails for
                                   another reason."""
        self.find_vm(label)

        try:
            log.debug("Stopping VM %s", label)
            taskid = self.vm.status.stop.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger stop: %s" % e)

        task = self.wait_for_task(taskid)
        if not task:
            raise CuckooMachineError("Timeout expired while stopping")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Stop failed: %s" % task["exitstatus"])
