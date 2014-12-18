

import logging
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooDependencyError



try:
    import XenAPI
    HAVE_XENAPI = True
except ImportError:
    HAVE_XENAPI = False


log = logging.getLogger(__name__)


class XenServerMachinery(Machinery):

    LABEL = "uuid"

    def _initialize_check(self):
        """Check XenServer configuration, initialize a Xen API connection, and
        verify machine validity.
        """

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

        try:
            self.session = XenAPI.Session(self.options.xenserver.url)
        except:
            raise CuckooMachineError("Could not connect to XenServer: invalid "
                                     "or incorrect urlm please ensure the url "
                                     "is correct in xenserver.conf")

        try:
            self.session.xenapi.login_with_password(
                self.options.xenserver.user, self.options.xenserver.password
            )
        except:
            raise CuckooMachineError("Could not connect to XenServer: "
                                     "incorrect credentials, please ensure the "
                                     "user and password are correct in "
                                     "xenserver.conf")

        for machine in self.machines():
            uuid = machine.label
            self._check_vm(uuid)

            if machine.snapshot:
                self._check_snapshot(uuid, machine.snapshot)

        super(XenServerMachinery, self)._initialize_check()

    def _get_vm_ref(self, uuid):
        """Get a virtual machine reference.
        @param uuid: vm uuid
        """

        return self.session.xenapi.VM.get_by_uuid(uuid)

    def _get_vm_record(self, ref):
        """Get the virtual machine record.
        @param ref: vm reference
        """

        return self.session.xenapi.VM.get_record(ref)

    def _check_vm(self, uuid):
        """Check vm existence and validity.
        @param uuid: vm uuid
        """

        try:
            ref = self._get_vm_ref(uuid)
            vm = self._get_vm_record(ref)
        except XenAPI.Failure as e:
            raise CuckooMachineError("Vm not found: %s: %s" % uuid)

        if vm['is_a_snapshot']:
            raise CuckooMachineError("Vm is a snapshot: %s" % uuid)

        if vm['is_a_template']:
            raise CuckooMachineError("Vm is a template: %s" % uuid)

        if vm['is_control_domain']:
            raise CuckooMachineError("Vm is a control domain: %s" % uuid)

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

        if not snapshot['is_a_snapshot']:
            raise CuckooMachineError("Invalid snapshot: %s" % snapshot_uuid)

        try:
            parent = self._get_vm_record(snapshot['snapshot_of'])
        except:
            raise CuckooMachineError("Invalid snapshot: %s" % snapshot_uuid)

        parent_uuid = parent['uuid']
        if parent_uuid != vm_uuid:
            raise CuckooMachineError("Snapshot does not belong to specified "
                                     "vm: %s" % snapshot_uuid)

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

        return vm['power_state'] == 'Halted'

    def start(self, uuid):
        """Start a virtual machine.
        @param uuid: vm uuid
        """

        vm_ref = self._get_vm_ref(uuid)
        vm = self._get_vm_record(vm_ref)

        if not self._is_halted(vm):
            raise CuckooMachineError("Vm is already running: %s" % uuid)

        snapshot = self._snapshot_from_vm_uuid(uuid)
        if snapshot:
            snapshot_ref = self._get_vm_ref(snapshot)
            try:
                log.debug("Reverting vm %s to snapshot %s", uuid, snapshot)
                self.session.xenapi.VM.revert(snapshot_ref)
                log.debug("Revert completed for vm %s", uuid)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Unable to revert vm %s: %s"
                                         % (uuid,e.details[0]))

            try:
                log.debug("Resuming reverted vm %s" % uuid)
                self.session.xenapi.VM.resume(vm_ref, False, False)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Unable to resume vm %s: %s"
                                         % (uuid, e.details[0]))
        else:
            log.debug("No snapshot found for vm, booting: %s" % uuid)
            try:
                self.session.xenapi.VM.start(vm_ref, False, False)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Unable to start vm %s: %s"
                                         % (uuid, e.details[0]))

        log.debug("Started vm: %s", uuid)

    def stop(self, uuid):
        """Stop a virtual machine.
        @param uuid: vm uuid
        """

        ref = self._get_vm_ref(uuid)
        vm = self._get_vm_record(ref)
        if self._is_halted(vm):
            log.warning("Trying to stop an already stopped machine: %s", uuid)
        else:
            try:
                self.session.xenapi.VM.hard_shutdown(ref)
            except XenAPI.Failure as e:
                raise CuckooMachineError("Error shutting down virtual machine: "
                                         "%s: %s" % (uuid, e.details[0]))

