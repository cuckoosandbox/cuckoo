# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
from lib.common.abstracts import Package
from lib.common.results import NetlogFile

class Strace(Package):
    """Generic analysis package. Uses shell based execution.
    """

    def __init__(self, *args, **kwargs):
        Package.__init__(self, *args, **kwargs)
        self.seen_pids = set()

    def start(self, path):
        """ https://blog.packagecloud.io/eng/2015/11/15/strace-cheat-sheet/
        """
        os.chmod(path, 0o755)
        try: os.mkdir("strace")
        except: pass # don't worry, it exists
        stderrfd = open("strace/strace.stderr", "wb")
        try:
             subprocess.Popen(["sh", "-c", "echo 0 > /proc/sys/kernel/yama/ptrace_scope"])
        except Exception as e:
            print e
        try:
            process = subprocess.Popen(["strace", "-ff", "-o", "strace/straced", path], stderr=stderrfd)
            return process.pid
        except:
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

    def finish(self):
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
