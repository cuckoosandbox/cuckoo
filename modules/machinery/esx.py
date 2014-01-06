# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# Copyright (C) 2013 Christopher Schmitt <cschmitt@tankbusta.net>
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import libvirt

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

class ESX(LibVirtMachinery):
    """Virtualization layer for ESXi/ESX based on python-libvirt."""
    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if configuration is invalid
        """
        if not self.options.esx.dsn:
            raise CuckooMachineError("ESX(i) DSN is missing, please add it to the config file")
        if not self.options.esx.username:
            raise CuckooMachineError("ESX(i) username is missing, please add it to the config file")
        if not self.options.esx.password:
            raise CuckooMachineError("ESX(i) password is missing, please add it to the config file")

        self.dsn = self.options.esx.dsn 
    
        super(ESX, self)._initialize_check()
  
    def _auth_callback(self, credentials, user_data):
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_AUTHNAME:
                credential[4] = self.options.esx.username
            elif credential[0] == libvirt.VIR_CRED_NOECHOPROMPT:
                credential[4] = self.options.esx.password
            else:
                raise CuckooCriticalError("ESX machinery did not recieve an object to inject a username or password into")

        return 0
    
    def _connect(self):
        try:
            self.auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_NOECHOPROMPT], self._auth_callback, None]
            return libvirt.openAuth(self.dsn, self.auth, 0)
        except libvirt.libvirtError as libvex:
            raise CuckooCriticalError("libvirt returned an exception on connection: %s" % libvex)
