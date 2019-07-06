# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess

from lib.core.config import Config
from lib.common.utils import determine_device_arch

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
            subprocess.check_call(["kill", "-9", str(self.pid)])
        except subprocess.CalledProcessError as e:
            log.error(
                "Failed to kill process with pid '%s': %s", self.pid, e
            )
            return
        log.info("Process with id %d is terminated." % self.pid)

    def dump_memory(self):
        """Dump the process memory."""
        config = Config(cfg="analysis.conf")
        log.info("Dumping memory of process with id: %s", self.pid)

        try:
            arch = determine_device_arch()
            if not arch:
                raise OSError("Failed to determine device architecture")

            args = ["chmod", "755", "bin/memdmp_%s" % arch]
            subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ).communicate()

            args = [
                "bin/memdmp_%s" % arch,
                "--remote", "%s:%s" % (config.ip, config.port),
                str(self.pid), "memory/%s-0.dmp" % self.pid
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            _, err = p.communicate()

            if p.returncode:
                raise OSError(err.decode().rstrip())
        except OSError as e:
            log.error("Failed to dump process memory. %s", e)

    @staticmethod
    def execute(cmd):
        """Execute a program.
        @param cmd: list of arguments.
        @return: instance of Process with new pid.
        """
        return Process(
            subprocess.Popen(cmd).pid
        )
