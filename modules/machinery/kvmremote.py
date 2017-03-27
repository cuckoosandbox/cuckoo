# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import xml.etree.ElementTree as ET
import libvirt

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooCriticalError


class KVMRemote(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    dsn = None

    def _list(self):
        """Overriden: we can't list having DSN per machine
            """
        raise NotImplementedError

    def _connect(self, label=None):
        """Connects to libvirt subsystem.
            @raise CuckooMachineError: when unable to connect to libvirt.
            """
        # Check if a connection string is available.

        dsn = self.options.get(label).get("dsn", None)

        if not dsn:
            raise CuckooMachineError("You must provide a proper "
                                     "connection string for "+label)

        try:
            return libvirt.open(dsn)
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot connect to libvirt")

    def _get_interface(self, mmanager_opts, machine_opts):
        if machine_opts.hypervisor:
            hyperv_cfg = self.options.get(machine_opts.hypervisor)
            return hyperv_cfg.interface

        return super(KVMRemote, self)._get_interface(mmanager_opts, machine_opts)

    def _initialize(self, module_name):
        """Read configuration.
            @param module_name: module name.
        """
        super(KVMRemote, self)._initialize(module_name)

        # Getting list of hypervisor sections
        hypervs_labels = self.options.get("kvmremote")["hypervisors"]
        hypervs_labels = ("".join(hypervs_labels.split())).split(",")

        for machine in self.machines():
            machine_cfg = self.options.get(machine.label)

            if machine_cfg.hypervisor:
                if machine_cfg.hypervisor not in hypervs_labels:
                    raise CuckooCriticalError(
                        "Unknown hypervisor %s for %s" % (machine_cfg.hypervisor, machine.label))

                hyperv_cfg = self.options.get(machine_cfg.hypervisor)

                machine_cfg.dsn = hyperv_cfg.dsn
