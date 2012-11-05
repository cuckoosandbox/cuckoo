# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import LibVirtMachineManager
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooMachineError
from lib.cuckoo.core.plugins import register_plugin

class KVM(LibVirtMachineManager):
    """Virtualization layer for KVM based on python-libvirt."""

    def set_dsn(self):
        """Set libvirt connection string."""
        self.dsn = "qemu:///system"

register_plugin("machinemanagers", KVM)
