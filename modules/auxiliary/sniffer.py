# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class Sniffer(Auxiliary):
    def start(self):
        tcpdump = self.options.get("tcpdump", "/usr/sbin/tcpdump")
        interface = self.options.get("interface")
        bpf = self.options.get("bpf", "")
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "dump.pcap")
        host = self.machine.ip

        if not os.path.exists(tcpdump):
            log.error("Tcpdump does not exist at path \"%s\", network "
                      "capture aborted", tcpdump)
            return

        mode = os.stat(tcpdump)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log.error("Tcpdump is not accessible from this user, "
                      "network capture aborted")
            return

        if not interface:
            log.error("Network interface not defined, network capture aborted")
            return

        pargs = [tcpdump, "-U", "-q", "-s", "0", "-i", interface, "-n"]

        # Trying to save pcap with the same user which cuckoo is running.
        try:
            user = getpass.getuser()
        except:
            pass
        else:
            pargs.extend(["-Z", user])

        pargs.extend(["-w", file_path])
        pargs.extend(["host", host])
        # Do not capture XMLRPC agent traffic.
        pargs.extend(["and", "not", "(", "host", host, "and", "port",
                      str(CUCKOO_GUEST_PORT), ")"])
        # Do not capture ResultServer traffic.
        pargs.extend(["and", "not", "(", "host",
                      str(Config().resultserver.ip), "and", "port",
                      str(Config().resultserver.port), ")"])

        if bpf:
            pargs.extend(["and", bpf])

        try:
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        except (OSError, ValueError):
            log.exception("Failed to start sniffer (interface=%s, host=%s, "
                          "dump path=%s)", interface, host, file_path)
            return

        log.info("Started sniffer with PID %d (interface=%s, host=%s, "
                 "dump path=%s)", self.proc.pid, interface, host, file_path)

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
                    log.debug("Error killing sniffer: %s. Continue", e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d: %s",
                                  self.proc.pid, e)
