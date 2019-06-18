# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import httpreplay.utils
import logging
import os.path
import tempfile
import threading

from cuckoo.common.abstracts import Auxiliary
from cuckoo.common.config import config
from cuckoo.core.rooter import rooter
from cuckoo.misc import Popen, cwd

log = logging.getLogger(__name__)
PORTS = []
PORT_LOCK = threading.Lock()

class Replay(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None
        self.port = None

    def pcap2mitm(self, pcappath, tlsmaster):
        """Translate a .pcap into a .mitm file."""
        mitmpath = tempfile.mktemp(suffix=".mitm")
        with open(mitmpath, "wb") as f:
            httpreplay.utils.pcap2mitm(pcappath, f, tlsmaster, True)
        return mitmpath

    def start(self):
        # Have to explicitly enable Replay.
        if not self.task.options.get("replay"):
            return

        if self.task.options.get("route"):
            log.error(
                "A network route must not be specified when performing a "
                "Replay analysis."
            )
            return

        # TODO We have to do version checking on mitmdump.
        mitmdump = self.options["mitmdump"]
        port_base = self.options["port_base"]
        certificate = self.options["certificate"]

        cert_path = cwd("analyzer", "windows", certificate)
        if not os.path.exists(cert_path):
            log.error("Mitmdump root certificate not found at path \"%s\" "
                      "(real path \"%s\"), man in the middle interception "
                      "aborted.", certificate, cert_path)
            return

        mitmpath = self.task.options["replay"]
        if not mitmpath.endswith((".pcap", ".mitm")):
            log.error(
                "Invalid filename (should end with .pcap or .mitm): %s. "
                "Can't proceed with replay analysis.", mitmpath
            )
            return

        # We support both .mitm and .pcap files.
        if mitmpath.endswith(".pcap"):
            tlsmaster = self.task.options.get("replay.tls")
            mitmpath = self.pcap2mitm(mitmpath, tlsmaster)

        if not os.path.getsize(mitmpath):
            log.error(
                "Empty .mitm file (potentially after conversion from .pcap), "
                "do you have the mitmproxy version 0.18.2 installed (in the "
                "same environment as Cuckoo)?"
            )
            log.info("Aborting Replay capabilities.")
            return

        PORT_LOCK.acquire()

        for port in xrange(port_base, port_base + 512):
            if port not in PORTS:
                self.port = port
                break

        PORTS.append(self.port)

        PORT_LOCK.release()

        # TODO Better access to self.machine and its related fields.
        machinery = config("cuckoo:cuckoo:machinery")
        rooter(
            "inetsim_enable", self.machine.ip,
            config("cuckoo:resultserver:ip"),
            config("%s:%s:interface" % (machinery, machinery)),
            str(config("cuckoo:resultserver:port")),
            "80:%d 443:%d" % (self.port, self.port)
        )

        args = [
            mitmdump, "-S", mitmpath,
            "--set", "server_replay_ignore_content",
            "--set", "server_replay_ignore_host",
            # With the port redirection provided by our InetSim support,
            # server_replay_ignore_port is strictly speaking irrelevant.
            # "--set", "server_replay_ignore_port",
            "--server-replay-kill-extra",
            "--mode", "transparent",
            "-k", "-q", "-p", "%d" % self.port,
        ]

        self.proc = Popen(args, close_fds=True)

        if "cert" in self.task.options:
            log.warning("A root certificate has been provided for this task, "
                        "however, this is overridden by the mitm auxiliary "
                        "module.")

        self.task.options["cert"] = certificate

        log.info(
            "Started PCAP replay PID %d (ip=%s, port=%d).",
            self.proc.pid, self.machine.resultserver_ip, self.port
        )

    def stop(self):
        machinery = config("cuckoo:cuckoo:machinery")
        self.port and rooter(
            "inetsim_disable", self.machine.ip,
            config("cuckoo:resultserver:ip"),
            config("%s:%s:interface" % (machinery, machinery)),
            str(config("cuckoo:resultserver:port")),
            "80:%d 443:%d" % (self.port, self.port)
        )

        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
                PORTS.remove(self.port)
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing mitmdump")
                        self.proc.kill()
                        PORTS.remove(self.port)
                except OSError as e:
                    log.debug("Error killing mitmdump: %s. Continue", e)
                except Exception as e:
                    log.exception("Unable to stop mitmdump with pid %d: %s",
                                  self.proc.pid, e)
