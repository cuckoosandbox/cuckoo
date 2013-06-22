# Copyright (C) 2012-2013 The MITRE Corporation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import xmlrpclib
import subprocess
from warnings import filterwarnings
import MySQLdb as Database
filterwarnings('ignore', category = Database.Warning)
import shutil
import os

from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.exceptions import CuckooCriticalError

log = logging.getLogger(__name__)


class Fog(MachineManager):
    """Manage physical sandboxes with Fog."""

    # physical machine states
    RUNNING = 'running'
    STOPPED = 'stopped'
    ERROR = 'error'

    def _initialize_check(self):
        """Ensures that credentials have been entered into the config file.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        if not self.options.fog.user or not self.options.fog.password:
            raise CuckooCriticalError("FOG machine credentials are missing, please add it to the config file")

        if not self.options.fog.mysqluser:
            raise CuckooCriticalError("MySQL user is missing, please add it to the config file")

        for machine in self.machines():
            if self._status(machine.label) != self.RUNNING:
                raise CuckooCriticalError("FOG machine is currently offline")
        
        pxecfg = str(CUCKOO_ROOT) + '/data/pxecfg/'
        
        if os.listdir(pxecfg) == []:
            raise CuckooCriticalError("PXE boot configuration folder is empty")

    def _get_machine(self, label):
        """Retreive all machine info given a machine's name.
        @param label: machine name.
        @return: machine dictionary (id, ip, platform, ...).
        @raises CuckooMachineError: if no machine with given label.
        """
        for m in self.machines():
            if label == m.label:
                return m

        raise CuckooMachineError("No machine with label: %s." % label)

    def start(self, label):
        """Start a physical machine.
        @param label: physical machine name.
        @raise CuckooMachineError: if unable to start.
        """
        # Check to ensure a given machine is running
        log.debug("Checking if %s is running." % label)
        status = self._status(label)
        if status == self.RUNNING:
            log.debug("Machine already running: %s." % label)

        elif status == self.STOPPED:
            self._wait_status(label, self.RUNNING)

        else:
            raise CuckooMachineError("Error occured while starting: " \
                                     "%s (STATUS=%s)" % (label, status))

    def stop(self, label):
        """Stops a physical machine.
        @param label: physical machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        # Collect machine credentials
        mach_n = self.options.fog.user
        mach_p = self.options.fog.password
        mach_creds = str(mach_n) + '%' + str(mach_p)
        
        # Collect MySQL credentials
        mysql_n = self.options.fog.mysqluser
        mysql_p = self.options.fog.mysqlpassword
        
        status = self._status(label)
        
        # Make a connection to MySQL
        db = Database.connect(host= "localhost",
                              user=mysql_n,
                              passwd=mysql_p,
                              db="fog")
        
        cursor = db.cursor()
        
        # Obtain Host ID number and MAC Address
        get_specs = "SELECT * FROM hosts WHERE hostName='" + str(label) + "'"
        
        try:
            cursor.execute(get_specs)
            results = cursor.fetchall()
            for row in results:
                hostID = row[0]
                hostMAC = row[8]
            except Database.Error, e:
                log.debug("Querying for Host ID & MAC failed with: %s." % e)
        
        mac = hostMAC.replace(':', '-')
        
        img_task = """INSERT INTO tasks(taskName, taskCreateTime,
                 taskCheckIn, taskHostID, taskState, taskCreateBy,
                 taskForce, taskType, taskNFSGroupID, taskNFSMemberID) 
                 VALUES ('', NOW(), NOW(), '""" + str(hostID) + """', '0', 'cuckoo', '0', 'D', '1', '1' )""" 
        
        if status == self.RUNNING:
            log.debug("Rebooting machine: %s." % label)
            machine = self._get_machine(label)
            shutdown = subprocess.Popen(['net', 'rpc', 'shutdown', '-I', label, '-U', creds, '-r', '-f', '--timeout=5'], stdout=subprocess.PIPE)
            output = shutdown.communicate()[0]
            
            if not "Shutdown of remote machine succeeded" in output:
                raise CuckooMachineError('Unable to initiate RPC request')

            else:
                log.debug("Reboot success: %s." % label)
                try:
                    cursor.execute(img_task)
                    db.commit()
                    src = str(CUCKOO_ROOT) + '/data/pxecfg/01-' + str(mac)
                    dst = '/tftpboot/pxelinux.cfg/01-' + str(mac)
                    shutil.copyfile(src, dst)
                except Database.Error, e:
                    # Rollback in case there is any error
                    log.debug("Adding imaging task to FOG DB failed with: %s." % e)
                    db.rollback()
                    raise CuckooMachineError('Unable to add imaging task to FOG DB')
                else:
                    log.debug("Imaging task success: %s." % label)
            
            db.close()

    def _list(self):
        """Lists physical machines installed.
        @return: physical machine names list.
        """
        active_machines = []
        for machine in self.machines():
            if self._status(machine.label) == self.RUNNING:
                active_machines.append(machine.label)

        return active_machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        # For physical machines, the agent can either be contacted or not.
        # However, there is some information to be garnered from potential
        # exceptions.
        log.debug("Getting status for machine: %s." % label)
        machine = self._get_machine(label)
        guest = GuestManager(machine.id, machine.ip, machine.platform)

        if not guest:
            raise CuckooMachineError('Unable to get status for machine: %s.'
                                     % label)

        else:
            try:
                status = guest.get_status()

            except xmlrpclib.Fault as e:
                # Contacted Agent, but it threw an error
                log.debug("Agent error: %s (%s) (Error: %s)."
                          % (machine.id, machine.ip, e))
                return self.ERROR

            except socket.error as e:
                # Could not contact agent
                log.debug("Agent unresponsive: %s (%s) (Error: %s)."
                          % (machine.id, machine.ip, e))
                return self.STOPPED

            except Exception as e:
                # TODO: Handle this better
                log.debug("Received unknown exception: %s." % e)
                return self.ERROR

        # If the agent responded successfully, the machine is running
        if status:
            return self.RUNNING

        return self.ERROR
