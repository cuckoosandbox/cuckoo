# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file was originally produced by Christopher Schmitt.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import time

from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

#Verify if we have the required vsphere/esxi module installed for communication
try:
    from pysphere import VIServer
except ImportError:
    raise CuckooMachineError("Need PySphere to use VMware_ESX MachineManager.")

log = logging.getLogger(__name__)

class VMware_ESX(MachineManager):
    """Virtualization layer for VMware ESX(i) using pysphere"""
    server = None
    server_type = None
    server_version = 0.0
    
    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """  
        if not self.options.vmware_esx.esx_server:
            raise CuckooMachineError("VMware ESX(i) server is missing, please add it to vmware_esx.conf")

        log.info("Attempting to establish connection to %s" % (self.options.vmware_esx.esx_server,))

        self.server = VIServer()
        self.server.connect(self.options.vmware_esx.esx_server, self.options.vmware_esx.esx_username, self.options.vmware_esx.esx_password)

        #Set some variables
        self.server_type = self.server.get_server_type()
        self.server_version = self.server.get_api_version()
        
        log.info("Connected to %s v%s at %s" % (self.server_type, self.server_version, self.options.vmware_esx.esx_server))
                
        # Consistency checks.
        for machine in self.machines():
            host, snapshot = self._parse_label(machine.label)
            self._check_snapshot(host, snapshot)
        super(VMware_ESX, self)._initialize_check()

    def _check_snapshot(self, host, snapshot):
        """Checks snapshot existance.
        @param host: file path
        @param snapshot: snapshot name
        @raise CuckooMachineError: if snapshot not found
        """
        try:
            logging.info("Checking for snapshot on %s" % (host))
            machine = self.server.get_vm_by_name(host)
            snapshots = machine.get_snapshots()
            exists = False
            
            if snapshots:
                for _snapshot in snapshots:
                    if _snapshot.get_name() == snapshot:
                        exists = True
                        logging.info("Snapshot %s for %s exists!" % (snapshot, host))
                        return True
                if not exists:
                    logging.info("Snapshot %s for %s does not exists!" % (snapshot, host))
                    return False
            else:
                raise CuckooMachineError("Unable to get snapshot list for %s." % host)
        except OSError as e:
            raise CuckooMachineError("Unable to get snapshot list for %s. Reason: %s" % (host, e))

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine identifier: path to vmx file and current snapshot name.
        @raise CuckooMachineError: if unable to start.
        """
        host, snapshot = self._parse_label(label)

        # Preventive check
        if self._is_running(host):
            raise CuckooMachineError("Machine %s is already running" % host)

        self._revert(host, snapshot)

        log.debug("Starting vm %s" % (host))
        try:
            machine = self.server.get_vm_by_name(host)
            #The revert process may start the VM after completion so let's check what our status is and decide what to do.
            status == machine.get_status()
            
            if status == "POWERING ON":
                return True
            elif status is not "POWERED ON":
                machine.power_on()
            else: #machine is on
                return True
        except OSError as e:
            raise CuckooMachineError("Unable to start machine %s in %s mode: %s"
                                     % (host, self.options.vmware.mode.upper(), e))

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine identifier: path to vmx file and current snapshot name.
        @raise CuckooMachineError: if unable to stop.
        """
        host, snapshot = self._parse_label(label)

        log.debug("Stopping vm %s" % host)
        if self._is_running(host):
            try:
                machine = self.server.get_vm_by_name(host)
                machine.power_off()
            except OSError as e:
                raise CuckooMachineError("Error shutting down machine %s: %s" % (host, e))
        else:
            log.warning("Trying to stop an already stopped machine: %s" % host)

    def _revert(self, host, snapshot):
        """Revets machine to snapshot.
        @param host: file path
        @param snapshot: snapshot name
        @raise CuckooMachineError: if unable to revert
        """
        log.debug("Revert snapshot for vm %s" % host)
        try:
            #TODO: Validation
            machine = self.server.get_vm_by_name(host)
            machine.revert_to_named_snapshot(snapshot)
        except OSError as e:
            raise CuckooMachineError("Unable to revert snapshot for machine %s: %s" % (host, e))

    def _is_running(self, host):
        """Checks if host is running.
        @param host: hostname
        @return: running status
        """
        try:
            status = self.server.get_vm_by_name(host).get_status()
            if status == "POWERED ON":
                logging.debug("_is_running: true")
                return True
            else:
                logging.debug("_is_running: false")
                return False
        except OSError as e:
            raise CuckooMachineError("Unable to check running status for %s. Reason: %s" % (host, e))

    def _parse_label(self, label):
        """Parse configuration file label.
        @param label: configuration option from config file
        @return: tuple of host file path and snapshot name
        """
        opts = label.strip().split(",")
        if len(opts) != 2:
            raise CuckooMachineError("Wrong label syntax for %s in vmware.conf: %s" % label)
        label = opts[0].strip()
        snapshot = opts[1].strip()
        return label, snapshot
