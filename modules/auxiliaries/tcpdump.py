# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_ROOT
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

class Tcpdump(Auxiliary):
    """Tcpdump Manager.

    This class handles the execution of the external tcpdump instance.
    """

    def __init__(self):
        super(Tcpdump, self).__init__()
        self.proc = None

    def start(self):
        """Start sniffing.
        @return: operation status.
        """
        if not self.options.tcpdump:
            log.error("Please specify a path to tcpdump, network capture aborted")
            return False
        
        if not os.path.exists(self.options.tcpdump):
            log.error("Tcpdump does not exist at path \"%s\", network capture "
                      "aborted" % self.tcpdump)
            return False

        mode = os.stat(self.options.tcpdump)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log.error("Tcpdump is not accessible from this user, network "
                      "capture aborted")
            return False

        if not self.machine:
            log.error("Please specify a virtual machine object to use, network capture aborted")
            return False

        if not self.machine.interface:
            log.error("Network interface not defined, network capture aborted")
            return False

        if not self.analysis_path:
            if self.task:
                self.analysis_path = os.path.join(CUCKOO_ROOT,
                                                  "storage",
                                                  "analyses",
                                                  str(self.task.id))
            else:
                log.error("You should specify the analysis path to save the pcap to, network capture aborted")
                return False

        file_path = os.path.join(self.analysis_path, "dump.pcap")

        pargs = [self.options.tcpdump, "-U", "-q", "-i", self.machine.interface, "-n"]

        # Trying to save pcap with the same user which cuckoo is running.
        try:
            user = getpass.getuser()
        except:
            pass
        else:
            pargs.extend(["-Z", user])
        pargs.extend(["-w", file_path])
        pargs.extend(["host", self.machine.ip])
        # Do not capture XMLRPC agent traffic.
        pargs.extend(["and", "not", "(", "host", self.machine.ip, "and", "port", str(CUCKOO_GUEST_PORT), ")"])
        # Do not capture ResultServer traffic.
        pargs.extend(["and", "not", "(", "host", str(Config().resultserver.ip), "and", "port", str(Config().resultserver.port), ")"])

        try:
            self.proc = subprocess.Popen(pargs,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.exception("Failed to start sniffer (interface=%s, host=%s, "
                          "dump path=%s)" % (self.machine.interface, self.machine.ip, file_path))
            return False

        log.info("Started sniffer (interface=%s, host=%s, dump path=%s)"
                 % (self.machine.interface, self.machine.ip, file_path))

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
                    # Avoid "trying to kill a died process" error.
                    log.debug("Error killing sniffer: %s. Continue" % e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d"
                                  % self.proc.pid)
                    return False

        return True
