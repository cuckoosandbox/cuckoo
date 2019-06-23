# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess

from lib.common.results import upload_from_buffer

log = logging.getLogger(__name__)

class Process(object):
    """Linux process."""

    def __init__(self, pid=0):
        """@param pid: PID.
        """
        self.pid = pid

    def is_alive(self):
        """Check if process is alive"""
        status = self.get_status()
        return status and "zombie" not in status.get("State", "")

    def get_status(self):
        """Get the status of a linux process"""
        try:
            status = open("/proc/%d/status" % self.pid, "r").readlines()
        except FileNotFoundError:
            log.error("Could not get process status for pid %d", self.pid)
            return {}

        pretty_status = [s.replace(" ", "").split(":") for s in status]
        return dict((i[0], i[1]) for i in pretty_status)

    def kill(self):
        """Kill the process."""
        try:
            subprocess.check_call(["kill", "-9", self.pid])
        except subprocess.CalledProcessError as e:
            log.error(
                "Failed to kill process with pid '%s': %s", self.pid, e
            )

    def dump_memory(self, frida_agent):
        """Dump the process memory using Frida.
        @param frida_agent: Frida agent instance.
        """
        log.info("Dumping memory of process id: %s", self.pid)

        ranges = frida_agent.call("enumerateRanges", "r--")
        for _range in ranges:
            base_addr = _range["base"]
            size = _range["size"]

            try:
                data = frida_agent.call("readBytes", [base_addr, size])
            except:  # TODO: fix memory access violations.
                continue

            dump_path = "memory/block-%s-%s.dmp" % (self.pid, base_addr)
            upload_from_buffer(data, dump_path)

    @staticmethod
    def execute(cmd):
        """Execute process.
        @param cmd: List of arguments.
        @return: instance of Process with new pid.
        """
        proc = subprocess.Popen(cmd)
        return Process(proc.pid)
