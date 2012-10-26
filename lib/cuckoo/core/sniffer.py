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
    """Sniffer Manager.

    This class handles the execution of the external tcpdump instance.
    """

    def __init__(self, tcpdump):
        """@param tcpdump: tcpdump path."""
        self.tcpdump = tcpdump
        self.proc = None

    def start(self, interface="eth0", host="", file_path=""):
        """Start sniffing.
        @param interface: network interface name.
        @param host: guest host IP address.
        @param file_path: tcpdump path.
        @return: operation status.
        """
        if not os.path.exists(self.tcpdump):
            log.error("Tcpdump does not exist at path \"%s\", network capture "
                      "aborted" % self.tcpdump)
            return False

        mode = os.stat(self.tcpdump)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log.error("Tcpdump is not accessible from this user, network "
                      "capture aborted")
            return False

        if not interface:
            log.error("Network interface not defined, network capture aborted")
            return False

        pargs = [self.tcpdump, '-U', '-q', '-i', interface, '-n', '-s', '1515']
        pargs.extend(['-w', file_path])
        pargs.extend(['not', 'port', str(CUCKOO_GUEST_PORT)])

        if host:
            pargs.extend(['and', 'host', host])

        try:
            self.proc = subprocess.Popen(pargs,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.exception("Failed to start sniffer (interface=%s, host=%s, "
                          "dump path=%s)" % (interface, host, file_path))
            return False

        log.info("Started sniffer (interface=%s, host=%s, dump path=%s)"
                 % (interface, host, file_path))

        return True

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing sniffer")
                        self.proc.kill()
                except OSError as e:
                    # Avoid "tying to kill a died process" error.
                    log.debug("Error killing sniffer: %s. Continue" % e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d"
                                  % self.proc.pid)
                    return False

        return True
