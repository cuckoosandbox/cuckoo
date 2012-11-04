# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import LibVirtMachineManager
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooMachineError

log = logging.getLogger(__name__)


class KVM(LibVirtMachineManager):
    """Virtualization layer for KVM based on python-libvirt."""

    def set_dsn(self):
        """Set libvirt connection string."""
        self.dsn = "qemu:///system"
