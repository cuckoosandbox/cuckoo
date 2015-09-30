# Copyright (C) 2012-2014 The MITRE Corporation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import xmlrpclib
import subprocess

from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class Physical(Machinery):
    """Manage physical sandboxes."""

    # Physical machine states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"

    def _initialize_check(self):
        """Ensures that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided or if
            one or more physical machines are offline.
        """
        if not self.options.physical.user or not self.options.physical.password:
            raise CuckooCriticalError("Physical machine credentials are missing, please add it to the config file")

        for machine in self.machines():
            if self._status(machine.label) != self.RUNNING:
                raise CuckooCriticalError("Physical machine is currently offline")

    def _get_machine(self, label):
        """Retrieve all machine info given a machine's name.
        @param label: machine name.
        @return: machine dictionary (id, ip, platform, ...).
        @raises CuckooMachineError: if no machine is available with the given label.
        """
        for m in self.machines():
            if label == m.label:
                return m

        raise CuckooMachineError("No machine with label: %s." % label)

    def start(self, label, task):
        """Start a physical machine.
        @param label: physical machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        # Check to ensure a given machine is running
        log.debug("Checking if machine %r is running.", label)
        status = self._status(label)
        if status == self.RUNNING:
            log.debug("Machine already running: %s.", label)

        elif status == self.STOPPED:
            self._wait_status(label, self.RUNNING)

        else:
            raise CuckooMachineError("Error occurred while starting: "
                                     "%s (STATUS=%s)" % (label, status))

    def stop(self, label):
        """Stops a physical machine.
        @param label: physical machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        # Since we are 'stopping' a physical machine, it must
        # actually be rebooted to kick off the re-imaging process
        n = self.options.physical.user
        p = self.options.physical.password
        creds = "%s%%%s" % (n, p)
        status = self._status(label)

        if status == self.RUNNING:
            log.debug("Rebooting machine: %s.", label)
            machine = self._get_machine(label)

            args = [
                "net", "rpc", "shutdown", "-I", machine.ip,
                "-U", creds, "-r", "-f", "--timeout=5"
            ]
            shutdown = subprocess.Popen(args, stdout=subprocess.PIPE)
            output, _ = shutdown.communicate()

            if "Shutdown of remote machine succeeded" not in output:
                raise CuckooMachineError("Unable to initiate RPC request")
            else:
                log.debug("Reboot success: %s." % label)

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
        """Gets current status of a physical machine.
        @param label: physical machine name.
        @return: status string.
        """
        # For physical machines, the agent can either be contacted or not.
        # However, there is some information to be garnered from potential
        # exceptions.
        log.debug("Getting status for machine: %s.", label)
        machine = self._get_machine(label)
        guest = GuestManager(machine.id, machine.ip, machine.platform)

        if not guest:
            raise CuckooMachineError("Unable to get status for machine: %s."
                                     % label)

        else:
            try:
                status = guest.server.get_status()
            except xmlrpclib.Fault as e:
                # Contacted Agent, but it threw an error.
                log.debug("Agent error: %s (%s) (Error: %s).",
                          machine.id, machine.ip, e)
                return self.ERROR
            except socket.error as e:
                # Could not contact agent.
                log.debug("Agent unresponsive: %s (%s) (Error: %s).",
                          machine.id, machine.ip, e)
                return self.STOPPED
            except Exception as e:
                # TODO Handle this better.
                log.debug("Received unknown exception: %s.", e)
                return self.ERROR

        # If the agent responded successfully, then the physical machine
        # is running
        if status:
            return self.RUNNING

        return self.ERROR
