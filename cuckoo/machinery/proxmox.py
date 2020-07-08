# Copyright (C) 2017 Menlo Security
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import time

from requests.exceptions import ConnectionError
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
        """Find a VM in the Proxmox cluster and return its node and vm proxy
        objects for extraction of additional data by other methods.

        @param label: the label of the VM to be compared to the VM's name in
                      Proxmox.
        @raise CuckooMachineError: if the VM cannot be found."""
        try:
            proxmox = ProxmoxAPI(self.options.proxmox.hostname,
                                 user=self.options.proxmox.username,
                                 password=self.options.proxmox.password,
                                 verify_ssl=False)
        except (ValueError, ConnectionError) as e:
            raise CuckooMachineError("Error connecting to Proxmox: %s" % e)

        # /cluster/resources[type=vm] will give us all VMs no matter which node
        # they reside on
        try:
            vms = proxmox.cluster.resources.get(type="vm")
        except ResourceException as e:
            raise CuckooMachineError("Error enumerating VMs: %s" % e)

        for vm in vms:
            # ignore incomplete entries which apparently can sometimes happen
            # when Proxmox Cluster nodes reboot
            if not {"name", "node", "type", "vmid"}.issubset(vm):
                continue

            if vm["name"] == label:
                # dynamically address
                # /nodes/<node>/{qemu,lxc,openvz,...}/<vmid> to get handle on
                # VM
                node = proxmox.nodes(vm["node"])
                hv = node.__getattr__(vm["type"])
                vm = hv.__getattr__(str(vm["vmid"]))

                # remember various request proxies for subsequent actions
                return vm, node

        raise CuckooMachineError("Not found")

    def wait_for_task(self, taskid, label, vm, node):
        """Wait for long-running Proxmox task to finish.

        @param taskid: id of Proxmox task to wait for
        @raise CuckooMachineError: if task status cannot be determined."""
        elapsed = 0
        while elapsed < self.timeout:
            try:
                task = node.tasks(taskid).status.get()
            except ResourceException as e:
                raise CuckooMachineError("Error getting status of task "
                                         "%s: %s" % (taskid, e))

            # extract operation name from task status for display
            operation = task["type"]
            if operation.startswith("qm"):
                operation = operation[2:]

            if task["status"] != "stopped":
                log.debug("%s: Waiting for operation %s (%s) to finish",
                          label, operation, taskid)
                time.sleep(1)
                elapsed += 1
                continue

            # VMs sometimes remain locked for some seconds after a task
            # completed. They will get stuck in that state if another operation
            # is attempted. So query the current VM status to extract the lock
            # status.
            try:
                status = vm.status.current.get()
            except ResourceException as e:
                raise CuckooMachineError("Couldn't get status: %s" % e)

            if "lock" in status:
                log.debug("%s: Task finished but VM still locked", label)
                if status["lock"] != operation:
                    log.warning("%s: Task finished but VM locked by different "
                                "operation: %s", label, operation)
                time.sleep(1)
                elapsed += 1
                continue

            # task is really, really done
            return task

        # timeout expired
        return None

    def find_snapshot(self, label, vm):
        """Find a specific or the most current snapshot of a VM.

        @param label: VM label for additional parameter retrieval
        @raise CuckooMachineError: if snapshots cannot be enumerated."""
        # use a statically configured snapshot name if configured without any
        # additional checks. User has to make sure it exists then.
        snapshot = self.db.view_machine_by_label(label).snapshot
        if snapshot:
            return snapshot

        # heuristically determine the most recent snapshot if no snapshot name
        # is explicitly configured.
        log.debug("%s: No snapshot configured, determining most recent one",
                  label)
        try:
            snapshots = vm.snapshot.get()
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

    def rollback(self, label, vm, node):
        """Roll back a VM's status to a statically configured or the most recent
        snapshot.

        @param label: VM label for lookup in Proxmox and additional parameter
                      retrieval.
        @raise CuckooMachineError: if snapshot cannot be found, reverting the
                                   machine to the snapshot cannot be triggered
                                   or times out or fails for another reason."""
        snapshot = self.find_snapshot(label, vm)
        if not snapshot:
            raise CuckooMachineError("No snapshot found - check config")

        try:
            log.debug("%s: Reverting to snapshot %s", label, snapshot)
            taskid = vm.snapshot(snapshot).rollback.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger rollback to "
                                     "snapshot %s: %s" % (snapshot, e))

        task = self.wait_for_task(taskid, label, vm, node)
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
        vm, node = self.find_vm(label)
        self.rollback(label, vm, node)

        try:
            status = vm.status.current.get()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't get status: %s" % e)

        if status["status"] == "running":
            log.debug("%s: Already running after rollback, no need to start "
                      "it", label)
            return

        try:
            log.debug("%s: Starting VM", label)
            taskid = vm.status.start.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger start: %s" % e)

        task = self.wait_for_task(taskid, label, vm, node)
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
        vm, node = self.find_vm(label)

        try:
            log.debug("%s: Stopping VM", label)
            taskid = vm.status.stop.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger stop: %s" % e)

        task = self.wait_for_task(taskid, label, vm, node)
        if not task:
            raise CuckooMachineError("Timeout expired while stopping")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Stop failed: %s" % task["exitstatus"])
