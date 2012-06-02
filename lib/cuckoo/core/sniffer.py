# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import logging
import subprocess

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class Sniffer:
    def __init__(self, tcpdump):
        self.tcpdump = tcpdump
        self.proc = None

    def start(self, interface="eth0", host="", file_path=""):
        if not os.path.exists(self.tcpdump):
            return False

        mode = os.stat(self.tcpdump)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            return False

        if not interface:
            return False

        pargs = [self.tcpdump, '-U', '-q', '-i', interface, '-n', '-s', '1515']
        pargs.extend(['-w', file_path])
        pargs.extend(['not', 'port', str(CUCKOO_GUEST_PORT)])

        if host:
            pargs.extend(['and', 'host', host])

        try:
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.error("Failed to start sniffer (interface=%s, host=%s, dump path=%s): %s" % (interface, host, file_path, e.message))
            return False

        log.info("Started sniffer (interface=%s, host=%s, dump path=%s)" % (interface, host, file_path))

        return True

    def stop(self):
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    self.proc.kill()
                except Exception as e:
                    return False

        return True
