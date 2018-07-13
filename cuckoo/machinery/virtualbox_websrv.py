# Copyright (C) 2011-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from cuckoo.common.abstracts import Machinery
from cuckoo.misc import mkdir, cwd
from cuckoo.common.exceptions import (
    CuckooCriticalError, CuckooMachineError, CuckooDependencyError
)

try:
    import remotevbox
    HAVE_REMOTEVBOX = True
except ImportError:
    HAVE_REMOTEVBOX = False

log = logging.getLogger(__name__)


class VirtualBoxRemote(Machinery):
    """Virtualization layer for VirtualBox."""

    # VM states.
    SAVED = "Saved"
    RUNNING = "Running"
    POWEROFF = "PoweredOff"
    ABORTED = "Aborted"

    def __init__(self):
        if not HAVE_REMOTEVBOX:
            raise CuckooDependencyError(
                "Couldn't import remotevbox, please install it (using "
                "`pip install -U remotevbox`)"
            )

        super(VirtualBoxRemote, self).__init__()

    def __initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        super(VirtualBoxRemote, self)._initialize(module_name)

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooCriticalError: if VirtualBox Web Service is
        not available remotely or some configuration variables are
        not set or wrong.
        """
        if not self.options.virtualbox_websrv.url:
            raise CuckooCriticalError(
                "VirtualBox Web Service URL is missing, please add it to the "
                "virtualbox_websrv.conf configuration file!"
            )

        if not self.options.virtualbox_websrv.remote_storage:
            raise CuckooCriticalError(
                "VirtualBox host path is missing, please add remote_storage "
                "to the virtualbox_websrv.conf configuration file!"
            )

        if not os.access(cwd("storage"), os.F_OK | os.W_OK | os.X_OK):
            raise CuckooCriticalError(
                "Not enough permissions to work with remote storage"
            )

        mkdir(cwd("storage", "analyses"))
        mkdir(cwd("storage", "binaries"))

        if self.options.virtualbox_websrv.mode not in ("gui", "headless"):
            raise CuckooCriticalError(
                "VirtualBox has been configured to run in a non-supported "
                "mode: %s. Please upgrade your configuration to reflect "
                "either 'gui' or 'headless' mode!" %
                self.options.virtualbox_websrv.mode
            )

        if not self.options.virtualbox_websrv.debug:
            logging.getLogger("zeep").setLevel(logging.INFO)

        self.user = self.options.virtualbox_websrv.user or ""
        self.password = self.options.virtualbox_websrv.password or ""

        vbox = self._connect()

        super(VirtualBoxRemote, self)._initialize_check()

        # Restore each virtual machine to its snapshot. This will crash early
        # for users that don't have proper snapshots in-place, which is good.
        machines = vbox.list_machines()
        for machine in self.machines():
            if machine.label not in machines:
                continue

            vmachine = vbox.get_machine(machine.label)

            if machine.snapshot:
                vmachine.restore(machine.snapshot)
            else:
                vmachine.restore()

        vbox.disconnect()

    def _connect(self):
        """Connect to a VirtualBox WebService.
        @return remotevbox.IVirtualBox
        @raise remotevbox.exceptions.WebServiceConnectionError: if
        VirtualBox Web Service is not available
        @raise remotevbox.exceptions.WrongCredentialsError: if credentials
        are not valid"""
        try:
            vbox = remotevbox.connect(self.options.virtualbox_websrv.url,
                                      self.user,
                                      self.password)
        except remotevbox.exceptions.WebServiceConnectionError:
            raise CuckooCriticalError(
                "Can't connect to VirtualBox Web Service, check your network "
                "and if web service is really started"
            )
        except remotevbox.exceptions.WrongCredentialsError:
            raise CuckooCriticalError(
                "Wrong credentials supplied in virtualbox_websrv.conf "
                "configuration file!"
            )
        return vbox

    def _get_machine(self, vbox, label):
        """Get virtual machine by a label.
        @return remotevbox.IMachine
        @raise remotevbox.exceptions.FindMachineError: if unable to find
        machine
        """
        try:
            machine = vbox.get_machine(label)
        except remotevbox.exceptions.FindMachineError as e:
            raise CuckooCriticalError(
                "Machine %s not found: %s" % (label, e)
            )
        return machine

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Obtaining vm %s", label)

        vbox = self._connect()
        machine = self._get_machine(vbox, label)

        if machine.state() == self.RUNNING:
            log.debug("Turning off machine")
            machine.save()

        log.debug("Restoring machine")
        machine_conf = self.db.view_machine_by_label(label)
        try:
            if machine_conf.snapshot:
                machine.restore(machine_conf.snapshot)
            else:
                """Restore to a current snapshot"""
                machine.restore()
        except remotevbox.exceptions.MachineSnapshotNX as e:
            raise CuckooMachineError(
                "Snapshot not found: %s" % e
            )

        log.debug("Enable network tracing")
        try:
            machine.enable_net_trace(self.options.virtualbox_websrv.remote_storage +
                                     '/analyses/' +
                                     str(task.id) +
                                     '/dump.pcap')
        except remotevbox.exceptions.MachineEnableNetTraceError as e:
            CuckooMachineError(
                "Can't enable net trace: %s" % e
            )
        except remotevbox.exceptions.MachineSetTraceFileError as e:
            CuckooMachineError(
                "Can't enable net trace: %s" % e
            )

        log.debug("Start vm %s" % label)
        try:
            machine.launch()
        except remotevbox.exceptions.MachineLaunchError as e:
            CuckooMachineError(
                "Can't start virtual machine: %s" % e
            )

        vbox.disconnect()

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)
        vbox = self._connect()
        machine = self._get_machine(vbox, label)

        status = machine.state()
        if status == self.POWEROFF or status == self.ABORTED:
            raise CuckooMachineError(
                "Trying to stop an already stopped VM: %s" % label
            )

        try:
            machine.poweroff()
            machine.disable_net_trace()
        except (remotevbox.exceptions.MachineDiscardError,
                remotevbox.exceptions.MachineSaveError,
                remotevbox.exceptions.ProgressTimeout) as e:
            raise CuckooMachineError(
                "Failed powering off the machine: %s" % e
            )
        vbox.disconnect()

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """

        vbox = self._connect()
        machine = self._get_machine(vbox, label)

        filename = os.path.basename(path)
        task_id = os.path.basename(os.path.dirname(path))

        try:
            machine.lock()
            machine.coredump(self.options.virtualbox_websrv.remote_storage +
                             '/analyses/' +
                             str(task_id) +
                             '/' +
                             filename)
            machine.unlock()
        except OSError as e:
            raise CuckooMachineError(
                "Failed to take a memory dump of the machine "
                "with label %s: %s" % (label, e)
            )
        except remotevbox.exceptions.MachineCoredumpError as e:
            CuckooMachineError(
                "Failed to coredump machine: %s" % e
            )
        vbox.disconnect()
