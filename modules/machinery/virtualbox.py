# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VirtualBox(Machinery):
    """Virtualization layer for VirtualBox."""

    # VM states.
    SAVED = "saved"
    RUNNING = "running"
    POWEROFF = "poweroff"
    ABORTED = "aborted"
    ERROR = "machete"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        # VirtualBox specific checks.
        if not self.options.virtualbox.path:
            raise CuckooCriticalError("VirtualBox VBoxManage path missing, "
                                      "please add it to the config file")
        if not os.path.exists(self.options.virtualbox.path):
            raise CuckooCriticalError("VirtualBox VBoxManage not found at "
                                      "specified path \"%s\"" %
                                      self.options.virtualbox.path)

        # Base checks.
        super(VirtualBox, self)._initialize_check()

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError("Trying to start an already "
                                     "started vm %s" % label)

        machine = self.db.view_machine_by_label(label)
        virtualbox_args = [self.options.virtualbox.path, "snapshot", label]
        if machine.snapshot:
            log.debug("Using snapshot {0} for virtual machine "
                      "{1}".format(machine.snapshot, label))
            virtualbox_args.extend(["restore", machine.snapshot])
        else:
            log.debug("Using current snapshot for virtual machine "
                      "{0}".format(label))
            virtualbox_args.extend(["restorecurrent"])

        try:
            if subprocess.call(virtualbox_args,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               close_fds=True):
                raise CuckooMachineError("VBoxManage exited with error "
                                         "restoring the machine's snapshot")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed restoring the "
                                     "machine: %s" % e)

        self._wait_status(label, self.SAVED)

        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "startvm",
                                     label,
                                     "--type",
                                     self.options.virtualbox.mode],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    close_fds=True)
            output, err = proc.communicate()
            if err:
                raise OSError(err)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed starting the machine "
                                     "in %s mode: %s" %
                                     (self.options.virtualbox.mode.upper(), e))

        self._wait_status(label, self.RUNNING)

        # Handle network dumping through the internal VirtualBox functionality.
        if "nictrace" in machine.options:
            self.dump_pcap(label, task)

    def dump_pcap(self, label, task):
        """Dump the pcap for this analysis through the VirtualBox integrated
        nictrace functionality. This is useful in scenarios where multiple
        Virtual Machines are talking with each other in the same subnet (which
        you normally don't see when tcpdump'ing on the gatway)."""
        try:
            args = [
                self.options.virtualbox.path,
                "controlvm", label,
                "nictracefile1", self.pcap_path(task.id),
            ]
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            log.critical("Unable to set NIC tracefile (pcap file): %s", e)
            return

        try:
            args = [
                self.options.virtualbox.path,
                "controlvm", label,
                "nictrace1", "on",
            ]
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            log.critical("Unable to enable NIC tracing (pcap file): %s", e)
            return

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        if self._status(label) in [self.POWEROFF, self.ABORTED]:
            raise CuckooMachineError("Trying to stop an already stopped "
                                     "vm %s" % label)

        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "controlvm", label, "poweroff"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    close_fds=True)
            # Sometimes VBoxManage stucks when stopping vm so we needed
            # to add a timeout and kill it after that.
            stop_me = 0
            while proc.poll() is None:
                if stop_me < int(self.options_globals.timeouts.vm_state):
                    time.sleep(1)
                    stop_me += 1
                else:
                    log.debug("Stopping vm %s timeouted. Killing" % label)
                    proc.terminate()

            if proc.returncode != 0 and \
                    stop_me < int(self.options_globals.timeouts.vm_state):
                log.debug("VBoxManage exited with error "
                          "powering off the machine")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed powering off the "
                                     "machine: %s" % e)
        self._wait_status(label, [self.POWEROFF, self.ABORTED, self.SAVED])

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "list", "vms"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    close_fds=True)
            output, _ = proc.communicate()
        except OSError as e:
            raise CuckooMachineError("VBoxManage error listing "
                                     "installed machines: %s" % e)

        machines = []
        for line in output.split("\n"):
            try:
                label = line.split('"')[1]
                if label == "<inaccessible>":
                    log.warning("Found an inaccessible virtual machine, "
                                "please check its state.")
                else:
                    machines.append(label)
            except IndexError:
                continue

        return machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s" % label)
        status = None
        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "showvminfo",
                                     label,
                                     "--machinereadable"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    close_fds=True)
            output, err = proc.communicate()

            if proc.returncode != 0:
                # It's quite common for virtualbox crap utility to exit with:
                # VBoxManage: error: Details: code E_ACCESSDENIED (0x80070005)
                # So we just log to debug this.
                log.debug("VBoxManage returns error checking status for "
                          "machine %s: %s", label, err)
                status = self.ERROR
        except OSError as e:
            log.warning("VBoxManage failed to check status for machine %s: %s",
                        label, e)
            status = self.ERROR
        if not status:
            for line in output.split("\n"):
                state = re.match(r'VMState="(\w+)"', line, re.M | re.I)
                if state:
                    status = state.group(1)
                    log.debug("Machine %s status %s" % (label, status))
                    status = status.lower()
        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError("Unable to get status for %s" % label)

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """

        try:
            proc = subprocess.Popen([self.options.virtualbox.path, "-v"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    close_fds=True)
            output, err = proc.communicate()

            if proc.returncode != 0:
                # It's quite common for virtualbox crap utility to exit with:
                # VBoxManage: error: Details: code E_ACCESSDENIED (0x80070005)
                # So we just log to debug this.
                log.debug("VBoxManage returns error checking status for "
                          "machine %s: %s", label, err)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed return it's version: %s" % (e))

        if output[:1] == str(5):
            # VirtualBox version 5.x
            dumpcmd = "dumpvmcore"
        else:
            # VirtualBox version 4.x
            dumpcmd = "dumpguestcore"

        try:
            subprocess.call([self.options.virtualbox.path, "debugvm",
                             label, dumpcmd, "--filename", path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            close_fds=True)
            log.info("Successfully generated memory dump for virtual machine "
                     "with label %s to path %s", label, path)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed to take a memory "
                                     "dump of the machine with label %s: %s" %
                                     (label, e))
