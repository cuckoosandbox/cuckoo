# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import time
import logging
import platform

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)

class STAP(Auxiliary):
    """system-wide syscall trace with stap."""
    priority = -10 # low prio to wrap tightly around the analysis

    def __init__(self):
        self.config = Config(cfg="analysis.conf")
        self.fallback_strace = False

    def start(self):
        # helper function locating the stap module
        def has_stap(p):
            only_stap = [fn for fn in os.listdir(p) if fn.startswith("stap_") and fn.endswith(".ko")]
            if only_stap: return os.path.join(p, only_stap[0])
            return False

        # highest priority: if the vm config specifies the path
        if self.config.get("analyzer_stap_path", None) and os.path.exists(self.config.get("analyzer_stap_path")):
            path = self.config.get("analyzer_lkm_path")
        # next: if a module was uploaded with the analyzer for our platform
        elif os.path.exists(platform.machine()) and has_stap(platform.machine()):
            path = has_stap(platform.machine())
        # next: default path inside the machine
        elif os.path.exists("/root/.cuckoo") and has_stap("/root/.cuckoo"):
            path = has_stap("/root/.cuckoo")
        # next: generic module uploaded with the analyzer (single arch setup maybe?)
        elif has_stap("."):
            path = has_stap(".")
        else:
            # we can't find the stap module, fallback to strace
            log.warning("Could not find STAP LKM, falling back to strace.")
            return self.start_strace()

        stap_start = time.time()
        stderrfd = open("stap.stderr", "wb")
        self.proc = subprocess.Popen(["staprun", "-v", "-x", str(os.getpid()), "-o", "stap.log", path], stderr=stderrfd)

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

    def start_strace(self):
        try: os.mkdir("strace")
        except: pass # don't worry, it exists

        stderrfd = open("strace/strace.stderr", "wb")
        self.proc = subprocess.Popen(["strace", "-ff", "-o", "strace/straced", "-p", str(os.getpid())], stderr=stderrfd)
        self.fallback_strace = True
        return True

    def get_pids(self):
        if self.fallback_strace:
            return [self.proc.pid, ]
        return []

    def stop(self):
        try:
            r = self.proc.poll()
            log.debug("stap subprocess retval %r", r)
            self.proc.kill()
        except Exception as e:
            log.warning("Exception killing stap: %s", e)

        if os.path.exists("stap.log"):
            # now upload the logfile
            nf = NetlogFile("logs/all.stap")

            fd = open("stap.log", "rb")
            for chunk in fd:
                nf.sock.sendall(chunk) # dirty direct send, no reconnecting

            fd.close()
            nf.close()

        # in case we fell back to strace
        if os.path.exists("strace"):
            for fn in os.listdir("strace"):
                # we don't need the logs from the analyzer python process itself
                if fn == "straced.%u" % os.getpid(): continue

                fp = os.path.join("strace", fn)

                # now upload the logfile
                nf = NetlogFile("logs/%s" % fn)

                fd = open(fp, "rb")
                for chunk in fd:
                    nf.sock.sendall(chunk) # dirty direct send, no reconnecting

                fd.close()
                nf.close()
