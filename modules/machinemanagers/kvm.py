# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooMachineError

try:
    import libvirt
except ImportError:
    raise CuckooDependencyError("Unable to import libvirt")

log = logging.getLogger(__name__)


class KVM(MachineManager):
    """Virtualization layer for KVM based on python-libvirt."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if libvirt version is not supported.
        """
        # KVM specific checks.
        if not self._version_check():
            raise CuckooMachineError("Libvirt version is not supported, please get an updated version")
        # Preload VMs
        self.vms = self._fetch_machines()
        # Base checks.
        super(KVM, self)._initialize_check()

    def start(self, label):
        """Starts a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start virtual machine.
        """
        log.debug("Staring vm %s" % label)
        # Get current snapshot.
        conn = self._connect()
        try:
            snap = self.vms[label].hasCurrentSnapshot(flags=0)
        except libvirt.libvirtError:
            self._disconnect(conn)
            raise CuckooMachineError("Unable to get current snapshot for virtual machine %s" % label)

        # Revert to latest snapshot.
        if snap:
            try:
                self.vms[label].revertToSnapshot(self.vms[label].snapshotCurrent(flags=0), flags=0)
            except libvirt.libvirtError:
                raise CuckooMachineError("Unable to restore snapshot on virtual machine %s" % label)
            finally:
                self._disconnect(conn)
        else:
            self._disconnect(conn)
            raise CuckooMachineError("No snapshot found for virtual machine %s" % label)

    def stop(self, label):
        """Stops a virtual machine. Kill them all.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop virtual machine.
        """
        log.debug("Stopping vm %s" % label)
        # Force virtual machine shutdown.
        conn = self._connect()
        try:
            if not self.vms[label].isActive():
                log.debug("Trying to stop an already stopped vm %s. Skip" % label)
            else:
                self.vms[label].destroy() # Machete's way!
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error stopping virtual machine %s: %s" % (label, e))
        finally:
            self._disconnect(conn)

    def shutdown(self):
        """Override shutdown to free libvirt handlers, anyway they print errors."""
        super(KVM, self).shutdown()
        # Free handlers.
        self.vms = None

    def _connect(self):
        """Connects to libvirt subsystem.
        @raise CuckooMachineError: if cannot connect to libvirt.
        """
        try:
            return libvirt.open("qemu:///system")
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot connect to libvirt")

    def _disconnect(self, conn):
        """Disconnects to libvirt subsystem.
        @raise CuckooMachineError: if cannot disconnect from libvirt.
        """
        try:
            conn.close()
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot disconnect from libvirt")

    def _fetch_machines(self):
        """Fetch machines handlers.
        @return: dict with machine label as key and handle as value.
        """
        vms = {}
        for vm in self.machines:
            vms[vm.label] = self._lookup(vm.label)
        return vms

    def _lookup(self, label):
        """Search for a virtual machine.
        @param conn: libvirt connection handle.
        @param label: virtual machine name.
        @raise CuckooMachineError: if virtual machine is not found.
        """
        conn = self._connect()
        try:
            vm = conn.lookupByName(label)
        except libvirt.libvirtError:
                raise CuckooMachineError("Cannot found machine %s" % label)
        finally:
            self._disconnect(conn)
        return vm

    def _list(self):
        """List available virtual machines.
        @raise CuckooMachineError: if unable to list virtual machines.
        """
        conn = self._connect()
        try:
            names = conn.listDefinedDomains()
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot list domains")
        finally:
            self._disconnect(conn)
        return names

    def _version_check(self):
        """Check if libvirt release supports snapshots.
        @return: True or false.
        """
        if libvirt.getVersion() >= 8000:
            return True
        else:
            return False
