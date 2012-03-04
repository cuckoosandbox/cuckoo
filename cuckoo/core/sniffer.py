# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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
import logging
import subprocess

from cuckoo.config.cuckooconfig import CuckooConfig

class Sniffer:
    """
    Sniffer wrapper class.
    """
    
    def __init__(self, pcap_file):
        """
        Create a new Sniffer.
        @param pcap_file: path to PCAP file
        """
        self.tcpdump = CuckooConfig().sniffer_path()
        self.pcap_file = pcap_file
        self.proc = None
        self.guest_mac = None

        log = logging.getLogger("Sniffer")

    def start(self, interface, guest_mac):
        """
        Start sniffing.
        @param interface: network interface name to sniff
        @param guest_mac: virtual machine MAC address to filter
        @return: boolean identifying the success of the operation
        """  
        log = logging.getLogger("Sniffer.Start")
        self.guest_mac = guest_mac

        if not self.tcpdump:
            log.error("Invalid tcpdump path. Check your configuration.")
            return False

        if not os.path.exists(self.tcpdump):
            log.error("Cannot find tcpdump path at \"%s\". " \
                      "Please check your installation." % self.tcpdump)
            return False

        # Check for suid bit being set.
        mode = os.stat(self.tcpdump)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log.error("Tcpdump doesn't have SUID bit set.")
            return False

        if not interface or interface == "":
            log.error("Invalid network interface. Check your configuration.")
            return False

        # Thanks to KjellChr for improving this.
        pargs = [self.tcpdump, '-U', '-q', '-i', interface, '-n', '-s', '1515']
        pargs.extend(['-w', self.pcap_file])

        if self.guest_mac:
            pargs.extend(['ether', 'host', self.guest_mac])

        try:
            self.proc = subprocess.Popen(pargs)
        except Exception, why:
            log.error("Something went wrong while starting the sniffer: %s"
                      % why)
            return False

        log.info("Sniffer started monitoring %s." % self.guest_mac)
        return True

    def stop(self):
        """
        Stop sniffing.
        @return: boolean identifying the success of the operation
        """
        log = logging.getLogger("Sniffer.Stop")

        if self.proc != None and self.proc.poll() == None:
            try:
                self.proc.terminate()
            except Exception, why:
                log.error("Something went wrong while stopping sniffer: %s"
                          % why)
                return False

            log.info("Sniffer stopped monitoring %s." % self.guest_mac)
