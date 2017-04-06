# Copyright (C) 2015 eSentire, Inc (jacob.gajek@esentire.com).
# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import random
import re
import requests
import ssl
import time

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooMachineError
from cuckoo.common.exceptions import CuckooDependencyError
from cuckoo.common.exceptions import CuckooCriticalError

try:
    from pyVim.connect import SmartConnection
    HAVE_PYVMOMI = True
except ImportError:
    HAVE_PYVMOMI = False

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


class vSphere(Machinery):
    """vSphere/ESXi machinery class based on pyVmomi Python SDK."""

    # VM states
    RUNNING = "poweredOn"
    POWEROFF = "poweredOff"
    SUSPENDED = "suspended"
    ABORTED = "aborted"

    def __init__(self):
        if not HAVE_PYVMOMI:
            raise CuckooDependencyError(
                "Couldn't import pyVmomi, please install it (using "
                "`pip install -U pyvmomi`)"
            )

        super(vSphere, self).__init__()

    def _initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        super(vSphere, self)._initialize(module_name)

        # Initialize random number generator
        random.seed()

    def _initialize_check(self):
        """Runs checks against virtualization software when a machine manager
        is initialized.
        @raise CuckooCriticalError: if a misconfiguration or unsupported state
                                    is found.
        """
        self.connect_opts = {}

        if self.options.vsphere.host:
            self.connect_opts["host"] = self.options.vsphere.host
        else:
            raise CuckooCriticalError(
                "vSphere host address setting not found, please add it "
                "to the config file."
            )

        if self.options.vsphere.port:
            self.connect_opts["port"] = self.options.vsphere.port
        else:
            raise CuckooCriticalError(
                "vSphere port setting not found, please add it to the "
                "config file."
            )

        if self.options.vsphere.user:
            self.connect_opts["user"] = self.options.vsphere.user
        else:
            raise CuckooCriticalError(
                "vSphere username setting not found, please add it to "
                "the config file."
            )

        if self.options.vsphere.pwd:
            self.connect_opts["pwd"] = self.options.vsphere.pwd
        else:
            raise CuckooCriticalError(
                "vSphere password setting not found, please add it to "
                "the config file."
            )

        # Workaround for PEP-0476 issues in recent Python versions
        if self.options.vsphere.unverified_ssl:
            sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            sslContext.verify_mode = ssl.CERT_NONE
            self.connect_opts["sslContext"] = sslContext
            log.warn("Turning off SSL certificate verification!")

        # Check that a snapshot is configured for each machine
        # and that it was taken in a powered-on state
        try:
            with SmartConnection(**self.connect_opts) as conn:
                for machine in self.machines():
                    if not machine.snapshot:
                        raise CuckooCriticalError(
                            "Snapshot name not specified for machine %s, "
                            "please add it to the config file." %
                            machine.label
                        )

                    vm = self._get_virtual_machine_by_label(conn, machine.label)
                    if not vm:
                        raise CuckooCriticalError(
                            "Unable to find machine %s on vSphere host, "
                            "please update your configuration." %
                            machine.label
                        )

                    state = self._get_snapshot_power_state(vm, machine.snapshot)
                    if not state:
                        raise CuckooCriticalError(
                            "Unable to find snapshot %s for machine %s, "
                            "please update your configuration." %
                            (machine.snapshot, machine.label)
                        )

                    if state != self.RUNNING:
                        raise CuckooCriticalError(
                            "Snapshot for machine %s not in powered-on "
                            "state, please create one." % machine.label
                        )
        except CuckooCriticalError as e:
            raise e
        except Exception as e:
            raise CuckooCriticalError(
                "Couldn't connect to vSphere host: %s" % e
            )

        super(vSphere, self)._initialize_check()

    def start(self, label, task):
        """Start a machine.
        @param label: machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start machine.
        """
        name = self.db.view_machine_by_label(label).snapshot
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if vm:
                self._revert_snapshot(vm, name)
            else:
                raise CuckooMachineError(
                    "Machine %s not found on host" % label
                )

    def stop(self, label):
        """Stop a machine.
        @param label: machine name.
        @raise CuckooMachineError: if unable to stop machine
        """
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if vm:
                self._stop_virtual_machine(vm)
            else:
                raise CuckooMachineError(
                    "Machine %s not found on host" % label
                )

    def dump_memory(self, label, path):
        """Take a memory dump of a machine.
        @param path: path to where to store the memory dump
        @raise CuckooMachineError: if error taking the memory dump
        """
        name = "cuckoo_memdump_{0}".format(random.randint(100000, 999999))
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if vm:
                self._create_snapshot(vm, name)
                self._download_snapshot(conn, vm, name, path)
                self._delete_snapshot(vm, name)
            else:
                raise CuckooMachineError(
                    "Machine %s not found on host" % label
                )

    def _list(self):
        """List virtual machines on vSphere host"""
        ret = []
        with SmartConnection(**self.connect_opts) as conn:
            for vm in self._get_virtual_machines(conn):
                ret.append(vm.summary.config.name)
        return ret

    def _status(self, label):
        """Get power state of vm from vSphere host.
        @param label: virtual machine name
        @raise CuckooMachineError: if error getting status or machine not found
        """
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if not vm:
                raise CuckooMachineError(
                    "Machine %s not found on server" % label
                )

            status = vm.runtime.powerState
            self.set_status(label, status)
            return status

    def _get_virtual_machines(self, conn):
        """Iterate over all VirtualMachine managed objects on vSphere host"""
        def traverseDCFolders(conn, nodes, path=""):
            for node in nodes:
                if hasattr(node, "childEntity"):
                    for child, childpath in traverseDCFolders(conn, node.childEntity, path + node.name + "/"):
                        yield child, childpath
                else:
                    yield node, path + node.name

        def traverseVMFolders(conn, nodes):
            for node in nodes:
                if hasattr(node, "childEntity"):
                    for child in traverseVMFolders(conn, node.childEntity):
                        yield child
                else:
                    yield node

        self.VMtoDC = {}

        for dc, dcpath in traverseDCFolders(conn, conn.content.rootFolder.childEntity):
            for vm in traverseVMFolders(conn, dc.vmFolder.childEntity):
                if hasattr(vm.summary.config, "name"):
                    self.VMtoDC[vm.summary.config.name] = dcpath
                    yield vm

    def _get_virtual_machine_by_label(self, conn, label):
        """Return the named VirtualMachine managed object"""
        for vm in self._get_virtual_machines(conn):
            if hasattr(vm.summary.config, "name"):
                if vm.summary.config.name == label:
                    return vm

    def _get_snapshot_by_name(self, vm, name):
        """Return the named VirtualMachineSnapshot managed object for
        a virtual machine"""
        for ss in self._traverseSnapshots(vm.snapshot.rootSnapshotList):
            if ss.name == name:
                return ss.snapshot

    def _get_snapshot_power_state(self, vm, name):
        """Return the power state for a named VirtualMachineSnapshot object"""
        for ss in self._traverseSnapshots(vm.snapshot.rootSnapshotList):
            if ss.name == name:
                return ss.state

    def _create_snapshot(self, vm, name):
        """Create named snapshot of virtual machine"""
        log.info(
            "Creating snapshot %s for machine %s",
            name, vm.summary.config.name
        )

        task = vm.CreateSnapshot_Task(name=name,
                                      description="Created by Cuckoo sandbox",
                                      memory=True,
                                      quiesce=False)
        try:
            self._wait_task(task)
        except CuckooMachineError as e:
            raise CuckooMachineError("CreateSnapshot: %s" % e)

    def _delete_snapshot(self, vm, name):
        """Remove named snapshot of virtual machine"""
        snapshot = self._get_snapshot_by_name(vm, name)
        if snapshot:
            log.info(
                "Removing snapshot %s for machine %s",
                name, vm.summary.config.name
            )

            task = snapshot.RemoveSnapshot_Task(removeChildren=True)
            try:
                self._wait_task(task)
            except CuckooMachineError as e:
                log.error("RemoveSnapshot: {0}".format(e))
        else:
            raise CuckooMachineError(
                "Snapshot %s for machine %s not found" %
                (name, vm.summary.config.name)
            )

    def _revert_snapshot(self, vm, name):
        """Revert virtual machine to named snapshot"""
        snapshot = self._get_snapshot_by_name(vm, name)
        if snapshot:
            log.info(
                "Reverting machine %s to snapshot %s",
                vm.summary.config.name, name
            )

            task = snapshot.RevertToSnapshot_Task()
            try:
                self._wait_task(task)
            except CuckooMachineError as e:
                raise CuckooMachineError("RevertToSnapshot: %s" % e)
        else:
            raise CuckooMachineError(
                "Snapshot %s for machine %s not found" %
                (name, vm.summary.config.name)
            )

    def _download_snapshot(self, conn, vm, name, path):
        """Download snapshot file from host to local path"""

        # Get filespec to .vmsn or .vmem file of named snapshot
        snapshot = self._get_snapshot_by_name(vm, name)
        if not snapshot:
            raise CuckooMachineError(
                "Snapshot %s for machine %s not found" %
                (name, vm.summary.config.name)
            )

        memorykey = datakey = filespec = None
        for s in vm.layoutEx.snapshot:
            if s.key == snapshot:
                memorykey = s.memoryKey
                datakey = s.dataKey
                break

        for f in vm.layoutEx.file:
            if f.key == memorykey and (f.type == "snapshotMemory" or
                                       f.type == "suspendMemory"):
                filespec = f.name
                break

        if not filespec:
            for f in vm.layoutEx.file:
                if f.key == datakey and f.type == "snapshotData":
                    filespec = f.name
                    break

        if not filespec:
            raise CuckooMachineError("Could not find snapshot memory file")

        log.info("Downloading memory dump %s to %s", filespec, path)

        # Parse filespec to get datastore and file path.
        datastore, filepath = re.match(r"\[([^\]]*)\] (.*)", filespec).groups()

        # Construct URL request
        params = {
            "dsName": datastore,
            "dcPath": self.VMtoDC.get(vm.summary.config.name, "ha-datacenter")
        }
        headers = {
            "Cookie": conn._stub.cookie,
        }
        url = "https://%s:%s/folder/%s" % (
            self.connect_opts["host"], self.connect_opts["port"], filepath
        )

        # Stream download to specified local path
        try:
            response = requests.get(url, params=params, headers=headers,
                                    verify=False, stream=True)

            response.raise_for_status()

            with open(path, "wb") as localfile:
                for chunk in response.iter_content(16*1024):
                    localfile.write(chunk)

        except Exception as e:
            raise CuckooMachineError(
                "Error downloading memory dump %s: %s" %
                (filespec, e)
            )

    def _stop_virtual_machine(self, vm):
        """Power off a virtual machine"""
        log.info("Powering off virtual machine %s", vm.summary.config.name)
        task = vm.PowerOffVM_Task()
        try:
            self._wait_task(task)
        except CuckooMachineError as e:
            log.error("PowerOffVM: %s", e)

    def _wait_task(self, task):
        """Wait for a task to complete with timeout"""
        limit = datetime.timedelta(seconds=config("cuckoo:timeouts:vm_state"))
        start = datetime.datetime.utcnow()

        while True:
            if task.info.state == "error":
                raise CuckooMachineError("Task error")

            if task.info.state == "success":
                break

            if datetime.datetime.utcnow() - start > limit:
                raise CuckooMachineError("Task timed out")

            time.sleep(1)

    def _traverseSnapshots(self, root):
        """Recursive depth-first traversal of snapshot tree"""
        for node in root:
            if len(node.childSnapshotList) > 0:
                for child in self._traverseSnapshots(node.childSnapshotList):
                    yield child
            yield node
