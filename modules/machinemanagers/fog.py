# Copyright (C) 2012-2013 The MITRE Corporation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import xmlrpclib

from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class Fog(MachineManager):
    """Manage physical sandboxes with Fog."""

    # physical machine states
    RUNNING = 'running'
    STOPPED = 'stopped'
    ERROR = 'error'

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
        # Since we are 'stopping' a physical machine, it must
        # actually be rebooted to kick off the reimaging process
        machine = self._get_machine(label)
        guest = GuestManager(machine.id, machine.ip, machine.platform)
        status = self._status(label)
        if status == self.RUNNING:
            log.debug("Rebooting machine: %s." % label)
            guest.reboot()

        else:
            log.debug("Currently rebooting: %s." % label)

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
