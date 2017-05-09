# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import threading

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError, CuckooDependencyError

try:
    import XenAPI
    HAVE_XENAPI = True
except ImportError:
    HAVE_XENAPI = False

log = logging.getLogger(__name__)

class XenServer(Machinery):
    """Virtualization layer for XenServer using the XenAPI XML-RPC interface."""

    LABEL = "uuid"

    # Power States.
    RUNNING = "Running"
    PAUSED = "Paused"
    POWEROFF = "Halted"
    ABORTED = "Suspended"

    def _initialize_check(self):
        """Check XenServer configuration, initialize a Xen API connection, and
        verify machine validity.
        """
        self._sessions = {}

        if not HAVE_XENAPI:
            raise CuckooDependencyError("Unable to import XenAPI")

        if not self.options.xenserver.user:
            raise CuckooMachineError("XenServer username missing, please add "
                                     "it to xenserver.conf.")

        if not self.options.xenserver.password:
            raise CuckooMachineError("XenServer password missing, please add "
                                     "it to xenserver.conf")

        if not self.options.xenserver.url:
            raise CuckooMachineError("XenServer url missing, please add it to "
                                     "xenserver.conf")

        self._make_xenapi_session()

        for machine in self.machines():
            uuid = machine.label
            (ref, vm) = self._check_vm(uuid)

            if machine.snapshot:
                self._check_snapshot(uuid, machine.snapshot)
            else:
                self._check_disks_reset(vm)

        super(XenServer, self)._initialize_check()

    @property
    def session(self):
        tid = threading.current_thread().ident
        sess = self._sessions.get(tid, None)
        if sess is None:
            sess = self._make_xenapi_session(tid)
        return sess

    def _make_xenapi_session(self, tid=None):
        tid = tid or threading.current_thread().ident
        try:
            sess = XenAPI.Session(self.options.xenserver.url)
        except:
            raise CuckooMachineError("Could not connect to XenServer: invalid "
                                     "or incorrect url, please ensure the url "
                                     "is correct in xenserver.conf")

        try:
            sess.xenapi.login_with_password(
                self.options.xenserver.user, self.options.xenserver.password
            )
        except:
            raise CuckooMachineError("Could not connect to XenServer: "
                                     "incorrect credentials, please ensure "
                                     "the user and password are correct in "
                                     "xenserver.conf")
        self._sessions[tid] = sess
        return sess

    def _get_vm_ref(self, uuid):
        """Get a virtual machine reference.
        @param uuid: vm uuid
        """
        return self.session.xenapi.VM.get_by_uuid(uuid.lower())

    def _get_vm_record(self, ref):
        """Get the virtual machine record.
        @param ref: vm reference
        """
        return self.session.xenapi.VM.get_record(ref)

    def _get_vm_power_state(self, ref):
        """Get the virtual machine power state.
        @param ref: vm reference
        """
        return self.session.xenapi.VM.get_power_state(ref)

    def _check_vm(self, uuid):
        """Check vm existence and validity.
        @param uuid: vm uuid
        """
        try:
            ref = self._get_vm_ref(uuid)
            vm = self._get_vm_record(ref)
        except XenAPI.Failure as e:
            raise CuckooMachineError("Vm not found: %s: %s"
                                     % (uuid, e.details[0]))

        if vm["is_a_snapshot"]:
            raise CuckooMachineError("Vm is a snapshot: %s" % uuid)

        if vm["is_a_template"]:
            raise CuckooMachineError("Vm is a template: %s" % uuid)

        if vm["is_control_domain"]:
            raise CuckooMachineError("Vm is a control domain: %s" % uuid)

        return (ref, vm)

    def _check_snapshot(self, vm_uuid, snapshot_uuid):
        """Check snapshot existence and that the snapshot is of the specified
        vm uuid.
        @param vm_uuid: vm uuid
        @param snapshot_uuid: snapshot uuid
        """
        try:
            snapshot_ref = self._get_vm_ref(snapshot_uuid)
            snapshot = self._get_vm_record(snapshot_ref)
        except:
            raise CuckooMachineError("Snapshot not found: %s" % snapshot_uuid)

        if not snapshot["is_a_snapshot"]:
            raise CuckooMachineError("Invalid snapshot: %s" % snapshot_uuid)

        try:
            parent = self._get_vm_record(snapshot["snapshot_of"])
        except:
            raise CuckooMachineError("Invalid snapshot: %s" % snapshot_uuid)

        parent_uuid = parent["uuid"]
        if parent_uuid != vm_uuid:
            raise CuckooMachineError("Snapshot does not belong to specified "
                                     "vm: %s" % snapshot_uuid)

    def _check_disks_reset(self, vm):
        """Check whether each attached disk is set to reset on boot.
        @param vm: vm record
        """
        for ref in vm["VBDs"]:
            try:
                vbd = self.session.xenapi.VBD.get_record(ref)
            except:
                log.warning("Invalid VBD for vm %s: %s", vm["uuid"], ref)
                continue

            if vbd["type"] == "Disk":
                vdi_ref = vbd["VDI"]
                try:
                    vdi = self.session.xenapi.VDI.get_record(vdi_ref)
                except:
                    log.warning("Invalid VDI for vm %s: %s", vm["uuid"],
                                vdi_ref)
                    continue

                if vdi["on_boot"] != "reset" and vdi["read_only"] is False:
                    raise CuckooMachineError(
                        "Vm %s contains invalid VDI %s: disk is not reset on "
                        "boot. Please set the on-boot parameter to 'reset'."
                        % (vm["uuid"], vdi["uuid"]))

    def _snapshot_from_vm_uuid(self, uuid):
        """Get the snapshot uuid from a virtual machine.
        @param uuid: vm uuid
        """
        machine = self.db.view_machine_by_label(uuid)
        return machine.snapshot

    def _is_halted(self, vm):
        """Checks if the virtual machine is running.
        @param uuid: vm uuid
        """
        return vm["power_state"] == "Halted"

    def start(self, label, task):
        """Start a virtual machine.
        @param label: vm uuid
        @param task: task object.
        """
        vm_ref = self._get_vm_ref(label)
        vm = self._get_vm_record(vm_ref)

        if not self._is_halted(vm):
            raise CuckooMachineError("Vm is already running: %s", label)

        snapshot = self._snapshot_from_vm_uuid(label)
        if snapshot:
            snapshot_ref = self._get_vm_ref(snapshot)
            try:
                log.debug("Reverting vm %s to snapshot %s", label, snapshot)
                self.session.xenapi.VM.revert(snapshot_ref)
                log.debug("Revert completed for vm %s", label)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Unable to revert vm %s: %s"
                                         % (label, e.details[0]))

            try:
                log.debug("Resuming reverted vm %s", label)
                self.session.xenapi.VM.resume(vm_ref, False, False)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Unable to resume vm %s: %s"
                                         % (label, e.details[0]))
        else:
            log.debug("No snapshot found for vm, booting: %s", label)
            try:
                self.session.xenapi.VM.start(vm_ref, False, False)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Unable to start vm %s: %s"
                                         % (label, e.details[0]))

        log.debug("Started vm: %s", label)

    def stop(self, label=None):
        """Stop a virtual machine.
        @param label: vm uuid
        """
        ref = self._get_vm_ref(label)
        vm = self._get_vm_record(ref)
        if self._is_halted(vm):
            log.warning("Trying to stop an already stopped machine: %s", label)
        else:
            try:
                self.session.xenapi.VM.hard_shutdown(ref)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Error shutting down virtual machine:"
                                         " %s: %s" % (label, e.details[0]))

    def _list(self):
        """List available virtual machines.
        @raise CuckooMachineError: if unable to list virtual machines.
        """
        try:
            vm_list = []
            for ref in self.session.xenapi.VM.get_all():
                vm = self._get_vm_record(ref)
                vm_list.append(vm['uuid'])
        except:
            raise CuckooMachineError("Cannot list domains")
        else:
            return vm_list

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine uuid
        @return: status string.
        """
        ref = self._get_vm_ref(label)
        state = self._get_vm_power_state(ref)
        return state
