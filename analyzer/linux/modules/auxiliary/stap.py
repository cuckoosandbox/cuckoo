# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import time
import logging

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)

class STAP(Auxiliary):
    """system-wide syscall trace with stap."""
    priority = -10 # low prio to wrap tightly around the analysis

    def start(self):
        stap_start = time.time()
        self.proc = subprocess.Popen(["staprun", "-v", "-x", str(os.getpid()), "-o", "stap.log", "./stap_ee93ee85b7a46987ad2d3ff259d87065_549791.ko"], stderr=subprocess.PIPE)

        # read from stderr until the tap script is compiled
        # while True:
        #     if not self.proc.poll() is None:
        #         break
        #     line = self.proc.stderr.readline()
        #     print "DBG LINE", line
        #     if "Pass 5: starting run." in line:
        #         break

        time.sleep(10)

        stap_stop = time.time()
        log.info("STAP aux module startup took %.2f seconds" % (stap_stop - stap_start))
        return True

    def stop(self):
        try:
            self.proc.kill()
        except Exception as e:
            log.warning("Exception killing stap: %s", e)

        # now upload the logfile
        nf = NetlogFile("logs/all.stap")

        fd = open("stap.log", "rb")
        for chunk in fd:
            nf.sock.sendall(chunk) # dirty direct send, no reconnecting

        fd.close()
        nf.close()
