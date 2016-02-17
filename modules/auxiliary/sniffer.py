# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import getpass
import logging
import subprocess

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class Sniffer(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None

    def start(self):
        if not self.machine.interface:
            log.error("Network interface not defined, network capture aborted")
            return

        # Handle special pcap dumping options.
        if "nictrace" in self.machine.options:
            return

        tcpdump = self.options.get("tcpdump", "/usr/sbin/tcpdump")
        bpf = self.options.get("bpf", "")
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                 "%s" % self.task.id, "dump.pcap")

        if not os.path.exists(tcpdump):
            log.error("Tcpdump does not exist at path \"%s\", network "
                      "capture aborted", tcpdump)
            return

        # TODO: this isn't working. need to fix.
        # mode = os.stat(tcpdump)[stat.ST_MODE]
        # if (mode & stat.S_ISUID) == 0:
        #    log.error("Tcpdump is not accessible from this user, "
        #              "network capture aborted")
        #    return

        pargs = [
            tcpdump, "-U", "-q", "-s", "0", "-n",
            "-i", self.machine.interface,
        ]

        # Trying to save pcap with the same user which cuckoo is running.
        try:
            user = getpass.getuser()
            pargs.extend(["-Z", user])
        except:
            pass

        pargs.extend(["-w", file_path])
        pargs.extend(["host", self.machine.ip])

        if self.task.options.get("sniffer.debug") != "1":
            # Do not capture Agent traffic.
            pargs.extend([
                "and", "not", "(",
                "dst", "host", self.machine.ip, "and",
                "dst", "port", str(CUCKOO_GUEST_PORT),
                ")", "and", "not", "(",
                "src", "host", self.machine.ip, "and",
                "src", "port", str(CUCKOO_GUEST_PORT),
                ")",
            ])

            # Do not capture ResultServer traffic.
            pargs.extend([
                "and", "not", "(",
                "dst", "host", self.machine.resultserver_ip, "and",
                "dst", "port", self.machine.resultserver_port,
                ")", "and", "not", "(",
                "src", "host", self.machine.resultserver_ip, "and",
                "src", "port", self.machine.resultserver_port,
                ")",
            ])

            if bpf:
                pargs.extend(["and", "(", bpf, ")"])

        try:
            self.proc = subprocess.Popen(pargs)
        except (OSError, ValueError):
            log.exception(
                "Failed to start sniffer (interface=%s, host=%s, pcap=%s)",
                self.machine.interface, self.machine.ip, file_path,
            )
            return

        log.info(
            "Started sniffer with PID %d (interface=%s, host=%s, pcap=%s)",
            self.proc.pid, self.machine.interface, self.machine.ip, file_path,
        )

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
