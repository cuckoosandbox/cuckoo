# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from cuckoo.common.abstracts import LibVirtMachinery
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooMachineError

try:
    import libvirt
    HAVE_LIBVIRT = True
except ImportError:
    HAVE_LIBVIRT = False


class KVM(LibVirtMachinery):
    """KVM virtualization layer based on python-libvirt."""

    def _initialize_check(self):
        """Init KVM configuration to open libvirt dsn connection."""
        self._sessions = {}
        if not self.options.kvm.dsn:
            raise CuckooMachineError("KVM(i) DSN is missing, please add it to the config file")
        self.dsn = self.options.kvm.dsn
        super(KVM, self)._initialize_check()

    def _connect(self):
        """Return global connection."""
        try:
            return libvirt.open(self.dsn)
        except libvirt.libvirtError as libvex:
            raise CuckooCriticalError("libvirt returned an exception on connection: %s" % libvex)

    def _disconnect(self, conn):
        """Disconnect, ignore request to disconnect."""
        pass