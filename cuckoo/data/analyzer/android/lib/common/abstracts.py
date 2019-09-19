# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import json
import logging

from lib.core import Frida
from lib.api.process import Process
from lib.common.exceptions import CuckooFridaError

log = logging.getLogger(__name__)

class Package(object):
    """Base analysis package."""

    def __init__(self, options={}, analyzer=None):
        """@param options: options dict.
        @param analyzer: Analyzer instance.
        """
        self.options = options
        self.analyzer = analyzer

        self.pids = []
        self.frida_client = None

    def add_pid(self, pid):
        """Update list of monitored PIDs in the package context.
        @param pid: Process id.
        """
        if pid not in self.pids:
            self.pids.append(pid)
    
    def remove_pid(self, pid):
        """Update list of monitored PIDs in the package context.
        @param pid: Process id.
        """
        if pid in self.pids:
            self.pids.remove(pid)

    def start(self, target):
        """Run analysis package.
        @param path: sample path.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        # Update the list of monitored processes
        for pid in self.pids:
            if not Process(pid).is_alive():
                self.remove_pid(pid)

        return len(self.pids) != 0

    def instrument(self):
        """Start instrumentation of analysis package."""
        if not self.frida_client:
            log.error(
                "Failed to instrument the analysis package. Frida is not "
                "installed properly."
            )
            return

        # callbacks for newly-created children.
        self.frida_client.on_child_added_callback = self.add_pid
        self.frida_client.on_child_removed_callback = self.remove_pid

        if len(self.pids):
            # First pid in the list denotes the parent.
            pid = self.pids[0]
            # Instrument the process.
            self.frida_client.start(pid)
        else:
            log.error(
                "Failed to instrument the analysis package. No running "
                "processes found."
            )

    def execute(self, target):
        """Execute the sample.
        @param target: List of arguments.
        @return: True on success, False otherwise.
        """
        pid = None
        try:
            # Spawn the process with Frida..
            self.frida_client = Frida.Client(self.analyzer)
            pid = self.frida_client.spawn(target)
        except CuckooFridaError as e:
            log.error(
                "Failed to spawn application process with Frida: %s" % e
            )
            if os.path.exists(target[0]):
                # Execute the target in a new process..
                pid = Process.execute(target).pid

        success = pid is not None
        if success:
            self.add_pid(pid)
        return success

    def finish(self):
        """Finish run."""
        self.frida_client.abort()

        for pid in self.pids[::-1]:
            Process(pid).dump_memory()
            Process(pid).kill()

class Auxiliary(object):
    def __init__(self, options={}):
        self.options = options

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError
