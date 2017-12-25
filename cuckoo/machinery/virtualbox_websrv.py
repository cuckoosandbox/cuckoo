# Copyright (C) 2011-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from cuckoo.common.abstracts import Machinery
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
        not set.
        """
        if not self.options.virtualbox_websrv.url:
            raise CuckooCriticalError(
                "VirtualBox Web Service URL is missing, please add it to the "
                "virtualbox_websrv.conf configuration file!"
            )

        if (not self.options.virtualbox_websrv.user or
           not self.options.virtualbox_websrv.password):
            raise CuckooCriticalError(
                "VirtualBox Web Service user or password is missing, please "
                "add it to the virtualbox_websrv.conf configuration file!"
            )

        if not self.options.virtualbox_websrv.remote_storage:
            raise CuckooCriticalError(
                "VirtualBox host path is missing, please add remote_storage "
                "to the virtualbox_websrv.conf configuration file!"
            )

        if self.options.virtualbox_websrv.mode not in ("gui", "headless"):
            raise CuckooCriticalError(
                "VirtualBox has been configured to run in a non-supported "
                "mode: %s. Please upgrade your configuration to reflect "
                "either 'gui' or 'headless' mode!" %
                self.options.virtualbox_websrv.mode
            )

        if not self.options.virtualbox_websrv.debug:
            logging.getLogger("zeep").setLevel(logging.INFO)

        try:
            vbox = remotevbox.connect(self.options.virtualbox_websrv.url,
                                      self.options.virtualbox_websrv.user,
                                      self.options.virtualbox_websrv.password)
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

        super(VirtualBoxRemote, self)._initialize_check()

        # Restore each virtual machine to its snapshot. This will crash early
        # for users that don't have proper snapshots in-place, which is good.
        machines = vbox.list_machines()
        for machine in self.machines():
            if machine.label not in machines:
                continue

            vmachine = vbox.get_machine(machine.label)
            vmachine.restore(machine.snapshot)

        vbox.disconnect()

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Obtaining vm %s", label)
        vbox = remotevbox.connect(self.options.virtualbox_websrv.url,
                                  self.options.virtualbox_websrv.user,
                                  self.options.virtualbox_websrv.password)
        machine = vbox.get_machine(label)

        if machine.state() == self.RUNNING:
            raise CuckooMachineError(
                "Trying to start an already started VM: %s" % label
            )

        log.debug("Restoring machine and powering it off")
        machine.restore()

        if machine.state() != self.POWEROFF:
            machine.poweroff()

        log.debug("Enable network tracing")
        machine.enable_net_trace(self.options.virtualbox_websrv.remote_storage +
                                 '/analyses/' +
                                 str(task.id) +
                                 '/dump.pcap')

        log.debug("Start vm")
        machine.launch()

        vbox.disconnect()

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)
        vbox = remotevbox.connect(self.options.virtualbox_websrv.url,
                                  self.options.virtualbox_websrv.user,
                                  self.options.virtualbox_websrv.password)
        machine = vbox.get_machine(label)

        status = machine.state()

        # The VM has already been restored, don't shut it down again. This
        # appears to be a VirtualBox-specific state though, hence we handle
        # it here rather than in Machinery._initialize_check().
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

        vbox = remotevbox.connect(self.options.virtualbox_websrv.url,
                                  self.options.virtualbox_websrv.user,
                                  self.options.virtualbox_websrv.password)
        machine = vbox.get_machine(label)
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
        vbox.disconnect()
