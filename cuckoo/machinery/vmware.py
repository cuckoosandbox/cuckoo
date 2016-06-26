# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file was originally produced by Mike Tu.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import glob
import logging
import subprocess
import os.path
import shutil
import time

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VMware(Machinery):
    """Virtualization layer for VMware Workstation using vmrun utility."""
    LABEL = "vmx_path"

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.vmware.path:
            raise CuckooMachineError("VMware vmrun path missing, "
                                     "please add it to vmware.conf")

        if not os.path.exists(self.options.vmware.path):
            raise CuckooMachineError("VMware vmrun not found in "
                                     "specified path %s" %
                                     self.options.vmware.path)
        # Consistency checks.
        for machine in self.machines():
            vmx_path = machine.label

            snapshot = self._snapshot_from_vmx(vmx_path)
            self._check_vmx(vmx_path)
            self._check_snapshot(vmx_path, snapshot)

        # Base checks.
        super(VMware, self)._initialize_check()

    def _check_vmx(self, vmx_path):
        """Checks whether a vmx file exists and is valid.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if file not found or not ending with .vmx
        """
        if not vmx_path.endswith(".vmx"):
            raise CuckooMachineError("Wrong configuration: vm path not "
                                     "ending with .vmx: %s)" % vmx_path)

        if not os.path.exists(vmx_path):
            raise CuckooMachineError("Vm file %s not found" % vmx_path)

    def _check_snapshot(self, vmx_path, snapshot):
        """Checks snapshot existance.
        @param vmx_path: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if snapshot not found
        """
        try:
            p = subprocess.Popen([self.options.vmware.path,
                                  "listSnapshots", vmx_path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output, _ = p.communicate()
            output = output.decode("utf-8")
        except OSError as e:
            raise CuckooMachineError("Unable to get snapshot list for %s. "
                                     "Reason: %s" % (vmx_path, e))
        else:
            if output:
                return snapshot in output
            else:
                raise CuckooMachineError("Unable to get snapshot list for %s. "
                                         "No output from "
                                         "`vmrun listSnapshots`" % vmx_path)

    def start(self, vmx_path, task):
        """Start a virtual machine.
        @param vmx_path: path to vmx file.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        snapshot = self._snapshot_from_vmx(vmx_path)

        # Preventive check
        if self._is_running(vmx_path):
            raise CuckooMachineError("Machine %s is already running" %
                                     vmx_path)

        self._revert(vmx_path, snapshot)

        time.sleep(3)

        log.debug("Starting vm %s" % vmx_path)
        try:
            p = subprocess.Popen([self.options.vmware.path,
                                  "start", vmx_path,
                                  self.options.vmware.mode],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            if self.options.vmware.mode.lower() == "gui":
                output, _ = p.communicate()
                if output:
                    raise CuckooMachineError("Unable to start machine "
                                             "%s: %s" % (vmx_path, output))
        except OSError as e:
            mode = self.options.vmware.mode.upper()
            raise CuckooMachineError("Unable to start machine %s in %s "
                                     "mode: %s" % (vmx_path, mode, e))

    def stop(self, vmx_path):
        """Stops a virtual machine.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % vmx_path)
        if self._is_running(vmx_path):
            try:
                if subprocess.call([self.options.vmware.path,
                                    "stop", vmx_path, "hard"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE):
                    raise CuckooMachineError("Error shutting down "
                                             "machine %s" % vmx_path)
            except OSError as e:
                raise CuckooMachineError("Error shutting down machine "
                                         "%s: %s" % (vmx_path, e))
        else:
            log.warning("Trying to stop an already stopped machine: %s",
                        vmx_path)

    def _revert(self, vmx_path, snapshot):
        """Revets machine to snapshot.
        @param vmx_path: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if unable to revert
        """
        log.debug("Revert snapshot for vm %s" % vmx_path)
        try:
            if subprocess.call([self.options.vmware.path,
                                "revertToSnapshot", vmx_path, snapshot],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE):
                raise CuckooMachineError("Unable to revert snapshot for "
                                         "machine %s: vmrun exited with "
                                         "error" % vmx_path)
        except OSError as e:
            raise CuckooMachineError("Unable to revert snapshot for "
                                     "machine %s: %s" % (vmx_path, e))

    def _is_running(self, vmx_path):
        """Checks if virtual machine is running.
        @param vmx_path: path to vmx file
        @return: running status
        """
        try:
            p = subprocess.Popen([self.options.vmware.path, "list"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output, error = p.communicate()
        except OSError as e:
            raise CuckooMachineError("Unable to check running status for %s. "
                                     "Reason: %s" % (vmx_path, e))
        else:
            if output:
                return vmx_path.lower() in output.lower()
            else:
                raise CuckooMachineError("Unable to check running status "
                                         "for %s. No output from "
                                         "`vmrun list`" % vmx_path)

    def _snapshot_from_vmx(self, vmx_path):
        """Get snapshot for a given vmx file.
        @param vmx_path: configuration option from config file
        """
        vm_info = self.db.view_machine_by_label(vmx_path)
        return vm_info.snapshot

    def dump_memory(self, vmx_path, path):
        """Take a memory dump of the machine."""
        if not os.path.exists(vmx_path):
            raise CuckooMachineError("Can't find .vmx file {0}. Ensure to configure a fully qualified path in vmware.conf (key = vmx_path)".format(vmx_path))

        try:
            subprocess.call([self.options.vmware.path, "snapshot",
                             vmx_path, "memdump"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        except OSError as e:
            raise CuckooMachineError("vmrun failed to take a memory dump of the machine with label %s: %s" % (vmx_path, e))

        vmwarepath, _ = os.path.split(vmx_path)
        latestvmem = max(glob.iglob(os.path.join(vmwarepath, "*.vmem")),
                         key=os.path.getctime)

        # We need to move the snapshot to the current analysis directory as
        # vmware doesn't support an option for the destination path :-/
        shutil.move(latestvmem, path)

        # Old snapshot can be deleted, as it isn't needed any longer.
        try:
            subprocess.call([self.options.vmware.path, "deleteSnapshot",
                             vmx_path, "memdump"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        except OSError as e:
            raise CuckooMachineError("vmrun failed to delete the temporary snapshot in %s: %s" % (vmx_path, e))

        log.info("Successfully generated memory dump for virtual machine with label %s ", vmx_path)
