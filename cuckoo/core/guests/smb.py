# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import string
import random
import socket

try:
    from impacket import smb
    from impacket.dcerpc import transport
    from impacket.dcerpc import dcerpc
    from impacket.dcerpc import svcctl
except ImportError:
    raise MissingDependency("Impacket library was not found.")

from cuckoo.core.guests.manager import GuestManager
from cuckoo.core.exceptions import *


class WinGuestManager(GuestManager):
    """Implements a SMB/DCERPC windows host handler.
    @requires: You have to change windows XP default SMB access policy. Go to
    control panel -> administrative tools -> local security policy -> local
    policies -> security options -> choose "Network Access: Sharing and
    security model for local accounts" and change to "Classic: local users
    authenticates as themself".
    @note: This code was inspired by Impacket examples and Bernardo G. Damele 
    'keimpx' tool."""

    SMB_TIMEOUT = 20
    SMB_PORT = 445

    def __init__(self, address, user, password):
        GuestManager.__init__(self, address, user, password)

    def __connect(self):
       """"Connects to guest with a SMB session.
       @raise GuestAccessDenied: If cannot connect.
       """
       try:
           self.__smb_handler = smb.SMB('*SMBSERVER',
                                        remote_host = self._address,
                                        sess_port = self.SMB_PORT,
                                        timeout = self.SMB_TIMEOUT)
       except socket.error, why:
            raise GuestAccessDenied('Connection to host %s failed (%s)' 
                                    % (self._address, why[1]))

    def __login(self):
        """""Logon to guest.
        @raise GuestAccessDenied: if unable to access or connect to guest 
        """
        try:
            self.__smb_handler.login(self._user, self._password)
        except socket.error, why:
            raise GuestAccessDenied('Connection to host %s failed (%s)' 
                                    % (self._address, why[1]))
        except smb.SessionError, why:
            raise GuestAccessDenied('SMB exception: %s' 
                                    % str(why).split('code: ')[1])

    def __cd(self, path):
        """CDs into path.
        @param path: folder path
        """
        p = string.replace(path,'/','\\')
        if p[0] == '\\':
           self.__pwd = path
        else:
           self.__pwd += '/' + path
    
    def __dir(self):
        """Directory listing.
        @return: array of contents file names
        """
        self.__connect()
        self.__login()
        self.use('C$')
        res = []
        for f in self.__smb_handler.list_path(self.__share, pwd):
           res.append(f.get_longname())
        return res

    def __list_shares(self):
        """Lists guest's available shares.
        @return: list of shares
        """
        self.__connect()
        self.__login()
        shares = []
        for share in self.__smb_handler.list_shared():
            shares.append(share.get_name())
        return shares
    
    def __use(self, share_name=None):
        """Set share to be used.
        @param share_name: share name
        """ 
        self.__share = share_name
        self.__tid = self.__smb_handler.tree_connect(share_name)

    def __get(self, filename, callback):
        """Get a file.
        @param filename: file name
        @param callback: callback function
        """
        f = self.__pwd + '/' + filename
        pathname = string.replace(f,'/','\\')
        self.__smb_handler.retr_file(self.__share, pathname, callback)

    def __put(self, src_file, dst_file):
        """Copy a file.
        @param src_file: source file path
        @param dst_file: destination file path
        @raise GuestWriteDenied: if cannot write files to guest
        @raise AccessDenied: if cannot read files from local host
        """
        try:
            fp = open(src_file, 'rb')
        except IOError:
            raise AccessDenied('Unable to open file %s' % src_file)
        dst_file = '%s\\%s' % (self.__pwd, dst_file.replace('/', '\\'))
        try:
            self.__smb_handler.stor_file(self.__share, dst_file, fp.read)
        except smb.SessionError, why:
            raise GuestWriteDenied('Unable to create file %s or ' +
                                   'file already exists.' % dst_file)
        fp.close()

    def __test_share(self):
        """Test if admin share on drive C is available.
        @raise GuestWriteDenied: if C$ share was not found
        """
        if not "C$" in self.__list_shares():
            raise GuestWriteDenied('Share C$ was not found.')

    def __mkdir(self, path):
        """Creates a directory.
        @param path: directory path.
        @raise GuestWriteDenied: if unable to create folder
        """
        self.__test_share()
        self.__use('C$')
        self.__cd('\\')
        path = '%s\\%s' % (self.__pwd, path.replace('/', '\\'))
        try:
            self.__smb_handler.mkdir(self.__share, path)
        except smb.SessionError, why:
            raise GuestWriteDenied('Unable to create folder %s or directory \
already exists.' % path)

    def __svcctl_create(self, srv_name, path):
        """Create a service.
        @param srv_name: service name
        @param path: full qualified executable path
        """
        # Use new binding, create_service() is deprecated.
        self.__svc.CreateServiceW(self.__mgr_handle,
                                  srv_name.encode('utf-16le'),
                                  srv_name.encode('utf-16le'),
                                  path.encode('utf-16le'))

    def __svcctl_srv_manager(self, srv_name):
        """Open service manager.
        @param srv_name: service name
        """
        # Use new binding, open_service() is deprecated.
        self.__resp = self.__svc.OpenServiceW(self.__mgr_handle,
                                              srv_name.encode('utf-16le'))
        # Old binding handler:
        # self.__svc_handle = self.__resp.get_context_handle() 
        self.__svc_handle = self.__resp['ContextHandle']

    def __deploy(self, srv_name, path, args=None):
        """Deploy a new windows service.
        @param srv_name: service name
        @param path: executable full qualified path
        @param args: service arguments
        """
        self.__svcctl_connect()
        self.__svcctl_create(srv_name, path)
        self.__svcctl_srv_manager(srv_name)
        self.__svcctl_start(srv_name, args)

    def __smb_transport(self, pipe):
        """Starts a connection to a named pipe.
        @param pipe: named pipe
        @raise GuestAccessDenied: if unable to connect to host or pipe
        """
        self.__trans = transport.SMBTransport(dstip = self._address, 
                                              dstport = self.SMB_PORT, 
                                              filename = pipe)
        self.__trans.set_credentials(username = self._user,
                                     password = self._password)
        try:
            self.__trans.connect()
        except socket.error, why:
            raise GuestAccessDenied('Unable to connect to %s failed (%s)' 
                                    % (self._address, why[1]))
        except smb.SessionError, why:
            raise GuestAccessDenied('Unable to connect to pipe. SMB error: %s' 
                                    % str(why).split('code: ')[1])

    def __svcctl_connect(self):
        """Connects to service control (svcctl pipe)."""
        self.__smb_transport('svcctl')
        self.__dce = dcerpc.DCERPC_v5(self.__trans)
        self.__dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.__svc = svcctl.DCERPCSvcCtl(self.__dce)
        # Use new binding, open_manager() is deprecated.
        self.__resp = self.__svc.OpenSCManagerW()
        # Old binding
        # self.__mgr_handle = self.__resp.get_context_handle()
        self.__mgr_handle = self.__resp['ContextHandle']

    def __svcctl_start(self, srv_name, args=None):
        if args is None:
            args = []
        else:
            nargs = []
            for arg in str(args).split(' '):
                nargs.append(arg.encode('utf-16le'))
            args = nargs
            print args
        self.__svc.StartServiceW(self.__svc_handle, args)

    def __random_string(self, length):
        """Generate a random string.
        @param length: string length
        @return: random string
        """
        return ''.join(random.choice(string.letters + 
                                     string.digits) for i in xrange(length))

    def __xcopy(self, src_path, dst_path):
        """Copy a tree.
        @param src_path: source path
        @param dst_path: destination path
        @raise NotImplementedError: if trying to copy a not regular file or dir
        """
        for file in os.listdir(src_path):
            src_file = os.path.join(src_path, file)
            if os.path.islink(src_file) or os.path.ismount(src_file):
                raise NotImplementedError('Cannot copy of this type of files.')
            elif os.path.isdir(src_file):
                self.__mkdir(os.path.join(dst_path, file))
                self.__xcopy(src_file, os.path.join(dst_path, file))
            elif os.path.isfile(src_file):
                self.__put(src_file, os.path.join(dst_path, file))
            else:
                raise NotImplementedError('Cannot copy of this unkown file.')

    def start_analysis(self, sample=None):
        """Starts analysis.
        @param sample: sample file path
        """
        raise NotImplementedError
    
    def get_results(self, path=None):
        raise NotImplementedError