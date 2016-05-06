# Copyright (C) 2012-2014 The MITRE Corporation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import xmlrpclib
import subprocess

log = logging.getLogger(__name__)

try:
    import bs4
    import requests
    import wakeonlan.wol
    HAVE_FOG = True
except ImportError:
    HAVE_FOG = False
    log.critical(
        "The bs4, requests, and wakeonlan Python libraries are required for "
        "proper FOG integration with Cuckoo (please install them through "
        "`pip install bs4 requests wakeonlan`)."
    )

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.utils import TimeoutServer

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
        # TODO This should be moved to a per-machine thing.
        if not self.options.physical.user or not self.options.physical.password:
            raise CuckooCriticalError(
                "Physical machine credentials are missing, please add it to "
                "the Physical machinery configuration file."
            )

        self.fog_init()

        for machine in self.machines():
            status = self._status(machine.label)
            if status == self.STOPPED:
                # Send a Wake On Lan message (if we're using FOG).
                self.wake_on_lan(machine.label)
            elif status == self.ERROR:
                raise CuckooMachineError(
                    "Unknown error occurred trying to obtain the status of "
                    "physical machine %s. Please turn it on and check the "
                    "Cuckoo Agent." % machine.label
                )

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
        # actually be rebooted to kick off the re-imaging process.
        creds = "%s%%%s" % (
            self.options.physical.user, self.options.physical.password
        )

        if self._status(label) == self.RUNNING:
            log.debug("Rebooting machine: %s.", label)
            machine = self._get_machine(label)

            args = [
                "net", "rpc", "shutdown", "-I", machine.ip,
                "-U", creds, "-r", "-f", "--timeout=5"
            ]
            output = subprocess.check_output(args)

            if "Shutdown of remote machine succeeded" not in output:
                raise CuckooMachineError("Unable to initiate RPC request")
            else:
                log.debug("Reboot success: %s." % label)

            # Deploy a clean image through FOG, assuming we're using FOG.
            self.fog_queue_task(label)

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

        # The status is only used to determine whether the Guest is running
        # or whether it is in a stopped status, therefore the timeout can most
        # likely be fairly arbitrary. TODO This is a temporary fix as it is
        # not compatible with the new Cuckoo Agent, but it will have to do.
        url = "http://{0}:{1}".format(machine.ip, CUCKOO_GUEST_PORT)
        server = TimeoutServer(url, allow_none=True, timeout=60)

        try:
            status = server.get_status()
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

    def fog_query(self, uri, data={}):
        """Wrapper around requests for simplifying FOG API access. Assuming
        you can call what FOG is providing an API."""
        url = "http://%s/fog/management/index.php?%s" % (
            self.options.fog.hostname, uri,
        )

        data.update({
            "uname": self.options.fog.username,
            "upass": self.options.fog.password,
        })

        return requests.post(url, data=data)

    def fog_init(self):
        """Initiate by indexing FOG regarding all available machines."""
        self.fog_machines = {}
        if not HAVE_FOG or self.options.fog.hostname == "none":
            return

        # TODO Handle exceptions such as not being able to connect.
        r = self.fog_query("node=tasks&sub=listhosts")

        # Parse the HTML.
        b = bs4.BeautifulSoup(r.content, "html.parser")
        if not b.find_all("table"):
            raise CuckooCriticalError(
                "The supplied FOG username and/or password do not allow us "
                "to login into FOG, please configure the correct credentials."
            )

        # Mapping for physical machine hostnames to their mac address and uri
        # for "downloading" a safe image onto the host. Great piece of FOG API
        # usage here.
        for row in b.find_all("table")[0].find_all("tr")[1:]:
            hostname, macaddr, download, upload, advanced = row.find_all("td")
            self.fog_machines[hostname.text] = (
                macaddr.text, next(download.children).attrs["href"][1:],
            )

        # Check whether all our machines are available on FOG.
        for machine in self.machines():
            if machine.label not in self.fog_machines:
                raise CuckooMachineError(
                    "The physical machine %s has not been defined in FOG, "
                    "please investigate and configure the configuration "
                    "correctly." % machine.label
                )

    def fog_queue_task(self, hostname):
        """Queues a task with FOG to deploy the given machine after reboot."""
        if hostname in self.fog_machines:
            macaddr, download = self.fog_machines[hostname]
            self.fog_query(download)

    def wake_on_lan(self, hostname):
        """Start a machine that's currently shutdown."""
        if hostname in self.fog_machines:
            macaddr, download = self.fog_machines[hostname]
            wakeonlan.wol.send_magic_packet(macaddr)
