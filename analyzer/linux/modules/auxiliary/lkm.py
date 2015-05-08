# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import logging

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)

class LKM(Auxiliary):
    """helper LKM for sleep skipping etc"""

    def start(self):
        os.system("insmod probelkm.ko trace_descendants=1 target_pid=%u" % os.getpid())
        return True

    def stop(self):
        os.system("rmmod probelkm")

        # now upload the logfile
        nf = NetlogFile("logs/all.lkm")

        fd = open("/var/log/kern.log")
        for line in fd:
            if not "[probelkm]" in line: continue
            nf.sock.sendall(line) # dirty direct send, no reconnecting

        fd.close()
        nf.close()
