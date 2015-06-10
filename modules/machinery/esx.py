# Copyright (C) 2010-2015 Cuckoo Foundation.
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
        self.global_conn = self._global_connect()
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
        """
        return the already-connected single connection handle if set, otherwise set it.
        """  
        if self.global_conn == None:
            self.global_conn = self._global_connect()
        return self.global_conn

    def _global_connect(self):
        """
        set the single connection handle
        """
        try:
            self.auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_NOECHOPROMPT], self._auth_callback, None]
            return libvirt.openAuth(self.dsn, self.auth, 0)
        except libvirt.libvirtError as libvex:
            raise CuckooCriticalError("libvirt returned an exception on connection: %s" % libvex)
    
    def _disconnect(self, conn):
        """
        Using one global connection we now disconnect in the destructor, ignore requests to disconnect
        """
        pass
            
    def dump_memory(self, label, path):
        """
        Take a memory dump of the machine.

        @param label: Label for the Virtual Machine
        @param path: where to dump memory image file
        """

        from pysphere import VIServer
        from urlparse import urlparse
        from urllib import quote_plus
        import os, re

        log = logging.getLogger(__name__)

        log.debug('UGLYHACK: Connecting to ESXi (machine with label {})'.format(label))
        try:
            server = VIServer()
            address = urlparse(self.options.esx.dsn).netloc
            server.connect(address, self.options.esx.username, self.options.esx.password)
        except Exception as e:
            raise CuckooMachineError("Can't connect to ESXi WebAPI")

        log.debug('UGLYHACK: Creating snapshot for machine with label {}'.format(label))
        try:
            vm1 = server.get_vm_by_name(label)
            vm1.create_snapshot('memdump', memory=True, description='Memory dump made by cuckoo, should be deleted automatically')
        except Exception as e:
            raise CuckooMachineError('Failed to take a memory dump of the machine with label {}: {}'.format(label, e))
        log.debug('UGLYHACK: Downloading memory dump file for machine with label {}'.format(label))
        try:
            memdumppath = ''
            m = re.search('^\[(.*)\] (.*\/).*$', vm1.get_property('path'))
            ds = server.get_datastore_by_name(quote_plus(m.group(1)))
            ds.get_file(quote_plus('/' + m.group(2)), '/tmp/index' + label + '.tmp')
            memdumppath = self.find_last_snapshot(label)[0]
            os.remove('/tmp/index' + label + '.tmp')
            ds.get_file(memdumppath, path)
        except Exception as e:
            raise CuckooMachineError('Failed to download vmsn file (path {}) for machine with label {}: {}'.format(memdumppath, label, e))

        try:
            vm1.delete_named_snapshot("memdump")
        except Exception as e:
            raise CuckooMachineError('Failed to delete the temporary snapshot for machine with label {}: {}'.format(label, e))

        log.info('UGLYHACK: Successfully generated memory dump for virtual machine with label {}'.format(label))
        server.disconnect()

    def find_last_snapshot(self, label):
        """
        Find last snapshot file

        @param label: name of the VM
        @return: list for ithe last snapshot file, index 0: path, 1: filename, 2:date, 3:size
        """

        from bs4 import BeautifulSoup
        from datetime import datetime
        result = []
        soup = BeautifulSoup(open('/tmp/index' + label + '.tmp'))
        allrows = soup.findAll('table')[1].findAll('tr')
        for row in allrows:
            allcols = row.findAll('td')
            if len(allcols) == 3:
                path = row.find('a', href=True)['href']
                path = path[7:path.index('?')]
                tmp = []
                tmp.append(path)
                for col in allcols:
                    thestrings = [unicode(s) for s in col.findAll(text=True)]
                    thetext = ''.join(thestrings)
                    tmp.append(thetext)
                if tmp[1].endswith('vmsn'):
                    if len(result) > 0:
                        d1 = datetime.strptime(tmp[2], '%d-%b-%Y %H:%M')
                        d2 = datetime.strptime(result[2], '%d-%b-%Y %H:%M')
                        if d1 > d2:
                            result = tmp
                    else:
                        result = tmp
        return result
        
    def __del__(self):
        self.global_disconnect()