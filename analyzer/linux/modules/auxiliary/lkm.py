# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import logging
import platform

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)

class LKM(Auxiliary):
    """helper LKM for sleep skipping etc"""

    def __init__(self):
        self.config = Config(cfg="analysis.conf")

    def start(self):
        # highest priority: if the vm config specifies the path
        if self.config.get("analyzer_lkm_path", None) and os.path.exists(self.config.get("analyzer_lkm_path")):
            path = self.config.get("analyzer_lkm_path")
        # next: if the analyzer was uploaded with a module for our platform
        elif os.path.exists(os.path.join(platform.machine(), "probelkm.ko")):
            path = os.path.join(platform.machine(), "probelkm.ko")
        # next: default path inside the machine
        elif os.path.exists("/root/.cuckoo/probelkm.ko"):
            path = "/root/.cuckoo/probelkm.ko"
        # next: generic module uploaded with the analyzer (single arch setup maybe?)
        elif os.path.exists("probelkm.ko"):
            path = "probelkm.ko"
        else:
            return False

        os.system("insmod %s trace_descendants=1 target_pid=%u" % (path, os.getpid()))
        return True

    def stop(self):
        # i guess we don't need to unload at all
        #os.system("rmmod probelkm")

        # now upload the logfile
        nf = NetlogFile("logs/all.lkm")

        fd = open("/var/log/kern.log")
        for line in fd:
            if not "[probelkm]" in line: continue
            nf.sock.sendall(line) # dirty direct send, no reconnecting

        fd.close()
        nf.close()
