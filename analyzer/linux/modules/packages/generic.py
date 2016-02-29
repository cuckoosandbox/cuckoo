# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package

class Generic(Package):
    """Generic analysis package. Uses shell based execution.
    """

    def __init__(self, *args, **kwargs):
        Package.__init__(self, *args, **kwargs)
        self.seen_pids = set()

    def start(self, path):
        os.chmod(path, 0o755)
        return self.execute(["sh", "-c", path])

    def get_pids(self):
        probelkm_pids = set()

        fd = open("/var/log/kern.log")
        for line in fd:
            if not "[probelkm]" in line: continue
            if "forked to" in line:
                # [probelkm] task 2102@0x00007fa5d0b8b576 forked to 2107@0xffffffff81352f6d
                parts = line[line.find("[probelkm]"):].split()
                newtask = parts[-1]
                pid, rip = newtask.split("@")
                probelkm_pids.add(int(pid))

        new_pids = probelkm_pids - self.seen_pids
        self.seen_pids |= new_pids
        return list(new_pids)
