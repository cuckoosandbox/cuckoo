#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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

from cuckoo.core.logging import *
from cuckoo.core.config import *

# Load VirtualBox's SDK APIs.
try:
    import vboxapi
# If the module is not found we need to abort execution.
except ImportError:
    log("[Virtual Machine] Unable to locate \"vboxapi\" Python " \
        "library. Please verify your setup. Exiting...", "ERROR")
    sys.exit(-1)

VBOX = vboxapi.VirtualBoxReflectionInfo(False)
# This matches the minimum required version for VirtualBox.
VBOX_VERSION = "4."
# This is the wait for completion timeout.
VBOX_TIMEOUT = 120000

class VirtualMachine:
    def __init__(self, vm_id = None):
        vbm = vboxapi.VirtualBoxManager(None, None)
        self.vbox = vbm.vbox
        self.mgr = vbm.mgr

        self.mach = None
        self.name = None
        self.username = None
        self.password = None
        self.mac = None

        # If a virtual machine name is specified than open handle.
        if vm_id is not None:
            self.name = CuckooConfig().get_vm_name(vm_id)
            self.username = CuckooConfig().get_vm_username(vm_id)
            self.password = CuckooConfig().get_vm_password(vm_id)
        
            try:
                self.mach = self.vbox.findMachine(self.name)
                log("[Virtual Machine] Acquired virtual machine with name " \
                    "\"%s\"." % self.name)
                
                # Acquire virtual machines' MAC address.
                mac_raw = self.mach.getNetworkAdapter(0).MACAddress
                mac_blocks = [mac_raw[x:x+2] for x in xrange(0, len(mac_raw), 2)]
                self.mac = ':'.join(mac_blocks)
            except Exception, why:
                log("[Virtual Machine] Virtual machine \"%s\" not " \
                    "found: %s" % (self.name, why), "ERROR")

    def infos(self):
        if self.mach:
            # Check if machine is accessible.
            if not self.mach.accessible:
                log("[Virtual Machine] [Infos] Virtual machine \"%s\"" \
                    " is not accessible." % self.name, "ERROR")
                return False

            # Check virtual machine's state.
            if self.mach.state != VBOX.MachineState_Saved:
                log("[Virtual Machine] [Infos] Virtual machine \"%s\""      \
                    " is not in a correct state. Please check it has been " \
                    "powered off and that its snapshot is restored."
                    % self.name, "ERROR")
                return False
           
            # Print virtual machine's general informations.
            log("[Virtual Machine] [Infos] Virtual machine \"%s\" informations:"
                % self.name)
            log("\t\_| Name: %s" % self.mach.name)
            log("\t  | ID: %s" % self.mach.id)
            log("\t  | CPU Count: %s Core/s" % self.mach.CPUCount)
            log("\t  | Memory Size: %s MB" % self.mach.memorySize)
            log("\t  | VRAM Size: %s MB" % self.mach.VRAMSize)
        
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
            
            log("\t  | State: %s" % state)
            log("\t  | Current Snapshot: \"%s\""
                % self.mach.currentSnapshot.name)
            log("\t  | MAC Address: %s" % self.mac)
        else:
            log("[Virtual Machine] [Infos] No virtual machine handle.",
                "ERROR")
            return False
            
        return True
    
    def check(self):
        # Check if VirtualBox version is supported.
        if not re.match(VBOX_VERSION, self.vbox.version):
            log("[Virtual Machine] [Check] Your VirtualBox version" \
                " \"%s\" is not supported. You should upgrade to 4.x!"
                % self.vbox.version, "ERROR")
            return False
        else:
            log("[Virtual Machine] [Check] Your VirtualBox version is: " \
                "\"%s\", good!" % self.vbox.version)
        
        return True
        
    def start(self):
        if self.mach:
            try:
                # If the virtual machine has not been previously restored
                # correctly, I do it now.
                if self.mach.state == VBOX.MachineState_PoweredOff:
                    self.restore()

                # If at this point the virtual machine is not in correct state,
                # something must have seriously gone wrong.
                if self.mach.state != VBOX.MachineState_Saved:
                    log("[Virtual Machine] [Start] Cannot start virtual " \
                        "machine \"%s\", wrong machine state: %s."
                        % (self.mach.name, self.mach.state), "ERROR")
                    return False

                # Create VirtualBox session.
                self.session = self.mgr.getSessionObject(self.vbox)
                # Launch virtual machine with specified running mode.
                mode = CuckooConfig().get_vm_mode()

                if mode != "gui" and mode != "headless":
                    log("[Virtual Machine] [Start] Unknown mode \"%s\" " \
                        "for virtual machine \"%s.\". Aborted."
                        % (mode, self.mach.name), "ERROR")
                    return False
                
                progress = self.mach.launchVMProcess(self.session, mode, "")
                # Wait for task to complete with a 60 seconds timeout.
                progress.waitForCompletion(VBOX_TIMEOUT)
                # Check if execution was successful.
                if progress.resultCode != 0:
                    log("[Virtual Machine] [Start] Unable to start " \
                        "virtual machine \"%s\"." % self.mach.name, "ERROR")
                    return False
                else:
                    log("[Virtual Machine] [Start] Virtual machine \"%s\" " \
                        "starting in \"%s\" mode." % (self.mach.name, mode))
            except Exception, why:
                log("[Virtual Machine] [Start] Something went wrong while " \
                    "starting virtual machine \"%s\": %s."
                    % (self.mach.name, why), "ERROR")
                return False
        else:
            log("[Virtual Machine] [Start] No virtual machine handle.",
                "ERROR")
            return False
            
        return True
        
    def stop(self):
        if self.mach:
            try:
                # Check machine state.
                if self.mach.state != VBOX.MachineState_Running:
                    log("[Virtual Machine] [Stop] Virtual machine \"%s\"" \
                        " is not running." % self.mach.name, "ERROR")
                    return False
                
                # Poweroff the virtual machine.
                progress = self.session.console.powerDown()
                # Wait for task to complete with a 60 seconds timeout.
                progress.waitForCompletion(VBOX_TIMEOUT)
                # Check if poweroff was successful.
                if progress.resultCode != 0:
                    log("[Virtual Machine] [Stop] Unable to poweroff " \
                        "virtual machine \"%s\"." % self.mach.name, "ERROR")
                    return False
                else:
                    log("[Virtual Machine] [Stop] Virtual machine \"%s\" " \
                        "powered off successfully." % self.mach.name)
            except Exception, why:
                log("[Virtual Machine] [Stop] Something went wrong while " \
                    "powering off virtual machine \"%s\": %s."
                    % (self.mach.name, why), "ERROR")
                return False
        else:
            log("[Virtual Machine] [Stop] No virtual machine handle.",
                "ERROR")
            return False
            
        return True
        
    def restore(self):
        if self.mach:
            try:
                # Check machine state before proceeding.
                if self.mach.state != VBOX.MachineState_PoweredOff:
                    log("[Virtual Machine] [Restore] Virtual machine " \
                        "\"%s\" is not powered off." % self.mach.name, "ERROR")
                    return False
            
                # Create VirtualBox session.
                self.session = self.mgr.getSessionObject(self.vbox)

                # Lock is needed to create a session and modify the state of the 
                # current virtual machine.
                try:
                    self.mach.lockMachine(self.session, VBOX.LockType_Shared)
                except Exception, why:
                    log("[Virtual Machine] [Restore] Unable to " \
                        "lock machine \"%s\": %s." % (self.mach.name, why),
                        "ERROR")
                    return False
                
                # Restore virtual machine snapshot.
                try:
                    progress = self.session.console.restoreSnapshot(
                        self.mach.currentSnapshot)
                except Exception, why:
                    log("[Virtual Machine] [Restore] Unable to restore " \
                        "virtual machine \"%s\": %s." % (self.mach.name, why),
                        "ERROR")
                    return False

                # Wait for task to complete with a 60 seconds timeout.
                progress.waitForCompletion(VBOX_TIMEOUT)
                # Check if snapshot restoring was successful.
                if progress.resultCode != 0:
                    log("[Virtual Machine] [Restore] Unable to restore " \
                        "virtual machine \"%s\" snapshot."
                        % self.mach.name, "ERROR")
                    return False
                else:
                    log("[Virtual Machine] [Restore] Virtual machine " \
                        "\"%s\" successfully restored to current snapshot."
                        % self.mach.name)
                    
                # Unlock machine, release session.
                self.session.unlockMachine()
            except Exception, why:
                log("[Virtual Machine] [Restore] Something went wrong while " \
                    "restoring virtual machine \"%s\" snapshot: %s."
                    % (self.mach.name, why), "ERROR")
                return False
        else:
            log("[Virtual Machine] [Restore] No virtual " \
                "machine handle.", "ERROR")
            return False
            
        return True

    def execute(self, execName, args = None, timeout = None):
        # Check if program name is specified.
        if not execName or execName == "":
            return False

        if self.mach:
            # Check if the virtual machine is running.
            if self.mach.state != VBOX.MachineState_Running:
                log("[Virtual Machine] [Execute] Cannot execute "              \
                    "process \"%s\" because the virtual machine \"%s\" is not" \
                    " running." % (execName, self.mach.name), "ERROR")
                return False

            # Set execution flags.
            #execFlags = VBOX.ExecuteProcessFlag_None
            #execFlags = VBOX.ExecuteProcessFlag_WaitForProcessStartOnly
            execFlags = VBOX.ExecuteProcessFlag_Hidden # <-- Go for this!

            # If no custom timeout is specified, retrieve it from the
            # global configuration file.
            # The watchdog timeout shouldn't generally be specified.
            if not timeout:
                watchdog = int(CuckooConfig().get_analysis_watchdog_timeout())
                # Calculate timeout in milliseconds.
                timeout = watchdog * 1000
                log("[Virtual Machine] [Execute] Watchdog timeout is %d seconds."
                    % watchdog, "DEBUG")

            # Need a valid Windows account to execute process.
            if not self.username or not self.password:
                log("[Virtual Machine] [Execute] No valid username or" \
                    " password combination for virtual machine \"%s\"."
                    % self.mach.name, "ERROR")
                return False

            # Try to execute process.
            try:
                log("[Virtual Machine] [Execute] Attempting to execute guest " \
                    "process on virtual machine.", "DEBUG")

                guest = self.session.console.guest
                (progress, pid) = guest.executeProcess(
                    execName,
                    execFlags,
                    args,
                    None,
                    self.username,
                    self.password,
                    0)
            except Exception, why:
                log("[Virtual Machine] [Execute] Something went wrong" \
                    " while executing Cuckoo: %s"
                    % why, "ERROR")
                return False

            log("[Virtual Machine] [Execute] Cuckoo executing with PID"     \
                " %s on virtual machine \"%s\"."                            \
                % (pid, self.mach.name), "INFO")

            # Wait for the process to complete execution for the given timeout.
            try:            
                progress.waitForCompletion(timeout)
            except Exception, why:
                log("[Virtual Machine] [Execute] Something went wrong"        \
                    " while waiting for completion of Cuckoo on "             \
                    "virtual machine \"%s\"." % self.mach.name,
                    "ERROR")
                return False

            # Retrieve process exit code.
            try:
                (reason, code, flags) = guest.getProcessStatus(pid)
            except Exception, why:
                code = "Unknown"

            exit_why = "[Virtual Machine] [Execute] Cuckoo exited with"     \
                       " code %s on virtual machine \"%s\"."                \
                       % (code, self.mach.name)

            if code == 0:
                log(exit_why, "INFO")
            else:
                log(exit_why, "ERROR")
                return False
        else:
            log("[Virtual Machine] [Execute] No virtual " \
                "machine handle." , "ERROR")
            return False

        return True
