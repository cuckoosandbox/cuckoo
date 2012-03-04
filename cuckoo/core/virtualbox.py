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

import re
import sys
import logging

from cuckoo.config.cuckooconfig import CuckooConfig

# Load VirtualBox's SDK APIs.
try:
    import vboxapi
# If the module is not found we need to abort execution.
except ImportError:
    sys.stderr.write("ERROR: Unable to locate \"vboxapi\" Python library. " \
                     "Please verify your installation. Exiting...\n")
    sys.exit(-1)

#------------------------------ Global Variables ------------------------------#
VBOX = vboxapi.VirtualBoxReflectionInfo(False)
VBOX_VERSION = "4."
# Wait for 5 minutes before aborting an action.
VBOX_TIMEOUT = 300000
#------------------------------------------------------------------------------#

class VirtualMachine:
    """
    Virtual Machine abstraction.
    """
    
    def __init__(self, vm_id = None):
        """
        Creates a new virtual machine.
        @param vm_id: virtual machine id
        """ 
        log = logging.getLogger("VirtualMachine")

        vbm = vboxapi.VirtualBoxManager(None, None)
        self.vbox = vbm.vbox
        self.mgr = vbm.mgr

        self.mach       = None
        self.name       = None
        self.username   = None
        self.password   = None
        self.mac        = None

        # If a virtual machine name is specified than open handle.
        if vm_id is not None:
            self.name = CuckooConfig().vm_name(vm_id)
            self.username = CuckooConfig().vm_username(vm_id)
            self.password = CuckooConfig().vm_password(vm_id)
        
            try:
                self.mach = self.vbox.findMachine(self.name)
                log.debug("Acquired virtual machine with name \"%s\"."
                          % self.name)
                
                # Acquire virtual machines' MAC address.
                mac_raw = self.mach.getNetworkAdapter(0).MACAddress
                mac_blocks = [mac_raw[x:x+2] for x in xrange(0, len(mac_raw), 2)]
                self.mac = ':'.join(mac_blocks)
            except Exception, why:
                log.error("Virtual machine \"%s\" not found: %s"
                          % (self.name, why))

    def infos(self):
        """
        Gets virtual machine infomation.
        @return: boolean identifying the success of the operation
        """
        log = logging.getLogger("VirtualMachine.Infos")

        if self.mach:
            # Check if machine is accessible.
            if not self.mach.accessible:
                log.error("Virtual machine \"%s\" is not accessible."
                          % self.name)
                return False

            # Check virtual machine's state.
            if self.mach.state == VBOX.MachineState_Aborted:
                log.error("Virtual machine \"%s\" is in aborted state, " \
                          "therefore it's not going to be added to pool."
                          % self.name)
                return False

            # Walk through known state values.
            if self.mach.state == VBOX.MachineState_PoweredOff:
                state = "Powered Off"
            elif self.mach.state == VBOX.MachineState_Saved:
                state = "Saved"
            elif self.mach.state == VBOX.MachineState_Aborted:
                state = "Aborted"
            elif self.mach.state == VBOX.MachineState_Running:
                state = "Running"
            else:
                state = "Not identified (%s)" % self.mach.state

            # Print virtual machine's general informations.
            log.info("Virtual machine \"%s\" information:" % self.name)
            log.info("\t\_| Name: %s" % self.mach.name)
            log.info("\t  | ID: %s" % self.mach.id)
            log.info("\t  | VRAM Size: %s MB" % self.mach.VRAMSize)
            log.info("\t  | OS Type: %s" % self.mach.OSTypeId)
            log.info("\t  | CPU Count: %s Core/s" % self.mach.CPUCount)
            log.info("\t  | Memory Size: %s MB" % self.mach.memorySize)   
            log.info("\t  | State: %s" % state)
            log.info("\t  | Current Snapshot: \"%s\""
                     % self.mach.currentSnapshot.name)
            log.info("\t  | MAC Address: %s" % self.mac)
        else:
            log.error("No virtual machine handle.")
            return False
            
        return True
    
    def check(self):
        """
        Checks if VirtualBox version is supported
        @return: boolean saying if VirtualBox version is supported or not
        """
        log = logging.getLogger("VirtualMachine.Check")

        # Check if VirtualBox version is supported.
        if not re.match(VBOX_VERSION, self.vbox.version):
            log.critical("Your VirtualBox version \"%s\" is not supported." \
                         "You should upgrade to 4.x!" % self.vbox.version)
            return False
        else:
            log.info("Your VirtualBox version is: \"%s\", good!"
                     % self.vbox.version)
        
        return True
        
    def start(self):
        """
        Starts virtual machine.
        @return: boolean identifying the success of the operation
        """
        log = logging.getLogger("VirtualMachine.Start")

        if self.mach:
            try:
                # If the virtual machine has not been previously restored
                # correctly, I do it now.
                if self.mach.state == VBOX.MachineState_PoweredOff:
                    self.restore()

                # If at this point the virtual machine is not in correct state,
                # something must have seriously gone wrong.
                if self.mach.state != VBOX.MachineState_Saved:
                    log.error("Cannot start virtual machine \"%s\", " \
                              "wrong state: %s."
                              % (self.mach.name, self.mach.state))
                    return False

                # Create VirtualBox session.
                session = self.mgr.getSessionObject(self.vbox)

                # Launch virtual machine with specified running mode.
                mode = CuckooConfig().virt_mode()

                if not mode:
                    log.error("No mode specified. Check your configuration.")
                    return False

                if mode.lower() != "gui" and mode.lower() != "headless":
                    log.error("Unknown mode \"%s\" for virtual machine " \
                              "\"%s.\". Abort." % (mode, self.mach.name))
                    return False
                
                progress = self.mach.launchVMProcess(session, mode, "")
                # Wait for task to complete with a 60 seconds timeout.
                progress.waitForCompletion(VBOX_TIMEOUT)
                # Check if execution was successful.
                if progress.resultCode != 0:
                    log.error("Failed to start virtual machine \"%s\"."
                              % self.mach.name)
                    return False
                else:
                    log.info("Virtual machine \"%s\" starting in \"%s\" mode."
                             % (self.mach.name, mode))
            except Exception, why:
                log.error("Something went wrong while starting virtual " \
                          "machine \"%s\": %s." % (self.mach.name, why))
                return False
        else:
            log.error("No virtual machine handle.")
            return False
            
        return True
        
    def stop(self):
        """
        Stops virtual machine.
        @return: boolean identifying the success of the operation
        """
        log = logging.getLogger("VirtualMachine.Stop")

        if self.mach:
            try:
                # Check machine state.
                if self.mach.state != VBOX.MachineState_Running:
                    log.debug("Virtual machine \"%s\" is not running."
                              % self.mach.name)
                    return False

                # Create VirtualBox session.
                session = self.mgr.getSessionObject(self.vbox)

                # Lock is needed to create a session and modify the state of the 
                # current virtual machine.
                try:
                    self.mach.lockMachine(session, VBOX.LockType_Shared)
                except Exception, why:
                    log.error("Unable to lock machine \"%s\": %s."
                              % (self.mach.name, why))
                    return False
                
                # Poweroff the virtual machine.
                progress = session.console.powerDown()
                # Wait for task to complete with a defined seconds timeout.
                progress.waitForCompletion(VBOX_TIMEOUT)
                # Check if poweroff was successful.
                if progress.resultCode != 0:
                    log.error("Unable to poweroff virtual machine \"%s\"."
                              % self.mach.name)
                    return False
                else:
                    log.info("Virtual machine \"%s\" powered off successfully."
                             % self.mach.name)

                # Unlock machine, release session.
                session.unlockMachine()
            except Exception, why:
                log.error("Something went wrong while powering off virtual " \
                          "machine \"%s\": %s" % (self.mach.name, why))
                return False
        else:
            log.error("No virtual machine handle.")
            return False
            
        return True
        
    def restore(self):
        """
        Restores virtual machine.
        @return: boolean identifying the success of the operation
        """
        log = logging.getLogger("VirtualMachine.Restore")

        if self.mach:
            try:
                ## Check machine state before proceeding.
                #if self.mach.state != VBOX.MachineState_PoweredOff:
                #    log.debug("Virtual machine is not powered off."
                #              % self.mach.name)
                #    return False
            
                # Create VirtualBox session.
                session = self.mgr.getSessionObject(self.vbox)

                # Lock is needed to create a session and modify the state of the 
                # current virtual machine.
                try:
                    self.mach.lockMachine(session, VBOX.LockType_Shared)
                except Exception, why:
                    log.error("Unable to lock machine \"%s\": %s."
                              % (self.mach.name, why))
                    return False
                
                # Restore virtual machine snapshot.
                try:
                    progress = session.console.restoreSnapshot(
                        self.mach.currentSnapshot)
                except Exception, why:
                    log.error("Unable to restore virtual machine \"%s\": %s."
                              % (self.mach.name, why))
                    return False

                # Wait for task to complete with a 60 seconds timeout.
                progress.waitForCompletion(VBOX_TIMEOUT)
                # Check if snapshot restoring was successful.
                if progress.resultCode != 0:
                    log.error("Unable to restore virtual machine \"%s\" snapshot."
                              % self.mach.name)
                    return False
                else:
                    log.info("Virtual machine \"%s\" successfully restored to" \
                             " current snapshot." % self.mach.name)
                    
                # Unlock machine, release session.
                session.unlockMachine()
            except Exception, why:
                log.error("Something went wrong while restoring virtual " \
                          "machine \"%s\" snapshot: %s" % (self.mach.name, why))
                return False
        else:
            log.error("No virtual machine handle.")
            return False
            
        return True

    def execute(self, exec_name, args = None, timeout = None):
        """ 
        Execute a process inside a virtual machine.
        @param exec_name: process to be executed
        @param args: arguments of process to be executed
        @param timeout: process execution timeout
        @return: boolean identifying the success of the operation
        """   
        log = logging.getLogger("VirtualMachine.Execute")

        # Check if program name is specified.
        if not exec_name or exec_name == "":
            return False

        if self.mach:
            # Check if the virtual machine is running.
            if self.mach.state != VBOX.MachineState_Running:
                log.error("Cannot execute process \"%s\" because the virtual " \
                          "machine \"%s\" is not running."
                          % (exec_name, self.mach.name))
                return False

            # Create VirtualBox session.
            session = self.mgr.getSessionObject(self.vbox)

            # Lock is needed to create a session and modify the state of the 
            # current virtual machine.
            try:
                self.mach.lockMachine(session, VBOX.LockType_Shared)
            except Exception, why:
                log.error("Unable to lock machine \"%s\": %s."
                          % (self.mach.name, why))
                return False

            # Set execution flags.
            exec_flags = VBOX.ExecuteProcessFlag_Hidden #

            # If no custom timeout is specified, retrieve it from the
            # global configuration file.
            # The watchdog timeout shouldn't generally be specified.
            if not timeout:
                watchdog = CuckooConfig().analysis_watchdog()
                # Calculate timeout in milliseconds.
                timeout = watchdog * 1000
                log.debug("Watchdog timeout is %d seconds." % watchdog)

            # Need a valid Windows account to execute process.
            if not self.username or not self.password:
                log.error("No valid username and password combination for " \
                          "virtual machine \"%s\"." % self.mach.name)
                return False

            # Try to execute process.
            try:
                log.debug("Trying to execute guest process on virtual machine.")

                guest = session.console.guest
                (progress, pid) = guest.executeProcess(
                    exec_name,
                    exec_flags,
                    args,
                    None,
                    self.username,
                    self.password,
                    0)
            except Exception, why:
                log.error("Something went wrong while executing Cuckoo: %s"
                          % why)
                return False

            log.info("Cuckoo analyzer running with PID %d on virtual " \
                     "machine \"%s\"." % (pid, self.mach.name))

            # Wait for the process to complete execution for the given timeout.
            try:            
                progress.waitForCompletion(timeout)
            except Exception, why:
                log.error("Something went wrong while waiting for completion" \
                          " of Cuckoo analyzer virtual machine \"%s\": %s"
                          % (self.mach.name, why))
                return False

            # Retrieve process exit code.
            try:
                (reason, code, flags) = guest.getProcessStatus(pid)
            except Exception, why:
                code = "Unknown"

            # Unlock machine, release session.
            session.unlockMachine()

            exit_why = "Cuckoo analyzer exited with code %d on virtual " \
                       "machine \"%s\"." % (code, self.mach.name)

            if code == 0:
                log.info(exit_why)
            else:
                log.error(exit_why)
                return False
        else:
            log.error("No virtual machine handle.")
            return False

        return True
