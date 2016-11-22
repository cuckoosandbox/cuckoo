# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import logging

log = logging.getLogger(__name__)

class Process:
    """Linux process."""
    first_process = True
    first_process_pid = None

    def __init__(self, pid=0):
        """@param pid: PID.
        """
        self.pid = pid

    def is_alive(self):
        if not os.path.exists("/proc/%u" % self.pid): return False
        status = self.get_proc_status()
        if not status: return False
        if "zombie" in status.get("State:", ""): return False
        return True

    def get_parent_pid(self):
        return self.get_proc_status().get("PPid", None)

    def get_proc_status(self):
        try:
            status = open("/proc/%u/status" % self.pid).readlines()
            status_values = dict((i[0], i[1]) for i in [j.strip().split(None, 1) for j in status])
            return status_values
        except:
            log.critical("could not get process status for pid %u", self.pid)
        return {}

    def execute(self, cmd):
        self.proc = proc = subprocess.Popen(cmd)
        self.pid = proc.pid
        return True
