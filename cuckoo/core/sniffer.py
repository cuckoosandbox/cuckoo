#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import stat
import subprocess

from cuckoo.core.config import *
from cuckoo.core.logging import *

TCPDUMP = "/usr/sbin/tcpdump"

class Sniffer:
    def __init__(self, pcap_file):
        self.ok = True
        self.pcap_file = pcap_file
        self.proc = None
        self.guest_mac = None

        if not os.path.exists(TCPDUMP):
            log("[Sniffer] [Init] Cannot find tcpdump path at \"%s\"." \
                " Please check your installation." %
                TCPDUMP, "ERROR")
            self.ok = False
            return

        # Check for suid bit being set.
        mode = os.stat(TCPDUMP)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log("[Sniffer] [Init] Tcpdump doesn't have SUID bit set.","ERROR")
            self.ok = False
            return

    def start(self, interface, guest_mac):
        self.guest_mac = guest_mac

        if not self.ok:
            return False

        # Thanks to KjellChr for improving this.
        pargs = [TCPDUMP, '-U', '-q', '-i', interface, '-n', '-s', '1515']
        pargs.extend(['-w', self.pcap_file])

        if self.guest_mac:
            pargs.extend(['ether', 'host', self.guest_mac])

        try:
            self.proc = subprocess.Popen(pargs)
        except Exception, why:
            log("[Sniffer] [Start] Something went wrong while " \
                "starting tcpdump: %s" % why, "ERROR")
            return False

        log("[Sniffer] [Start] Tcpdump started monitoring %s." % self.guest_mac)
        return True

    def stop(self):
        if self.proc != None and self.proc.poll() == None:
            try:
                self.proc.terminate()
            except Exception, why:
                log("[Sniffer] [Stop] Something went wrong while " \
                    "stopping tcpdump: %s" % why, "ERROR")
                return False

            log("[Sniffer] [Stop] Tcpdump stopped monitoring %s." % 
                self.guest_mac)
