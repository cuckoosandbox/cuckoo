# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import threading

from cuckoo.common.abstracts import Auxiliary
from cuckoo.common.config import config
from cuckoo.misc import cwd, Popen

log = logging.getLogger(__name__)
PORTS = []
PORT_LOCK = threading.Lock()

class MITM(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None

    def start(self):
        port_base = self.options["port_base"]
        certificate = self.options["certificate"]
        transparent_mode = config("auxiliary:mitm:transparent_mode")
        confdir = config("auxiliary:mitm:confdir")

        mitmdump = self.options["mitmdump"]
        if not os.path.exists(mitmdump):
            log.error("Mitmdump does not exist at path \"%s\", man in the "
                      "middle interception aborted.", mitmdump)
            return

        script = cwd(self.options["script"])
        if not os.path.exists(script):
            log.error("Mitmdump script file does not exist at path \"%s\", "
                      "man in the middle interception aborted.", script)
            return

        cert_path = cwd("analyzer", "windows", certificate)
        if not os.path.exists(cert_path):
            log.error("Mitmdump root certificate not found at path \"%s\" "
                      "(real path \"%s\"), man in the middle interception "
                      "aborted.", certificate, cert_path)
            return

        PORT_LOCK.acquire()

        for port in xrange(port_base, port_base + 512):
            if port not in PORTS:
                self.port = port
                break

        PORTS.append(self.port)

        PORT_LOCK.release()

        # Prepare the configuration for recovering TLS Master keys (useful for Wireshark)
        tlsmaster_mitm = cwd("storage", "analyses", "%d" % self.task.id, "tlsmaster.mitm")
        os.environ["MITMPROXY_SSLKEYLOGFILE"] = tlsmaster_mitm
        log.debug("TLS Master keys will be dropped in this file: "+tlsmaster_mitm)

        # Build arguments
        args = [
            mitmdump, "-q",
            "-s", '"{}" {}'.format(
                script, self.task.options.get("mitm", "")
            ).strip(),
            "-p", "%d" % self.port,
            "-w", cwd("dump.mitm", analysis=self.task.id),
        ]
        if transparent_mode:
            args.extend( ["--mode", "transparent", "--showhost"] )
        if confdir != "":
            confdir_path = cwd( str(confdir) )
            args.extend( ["--conf", confdir_path] )
            log.debug("MITM config dir '%s' will be used." % confdir_path)

        # Run mitmdump
        self.proc = Popen(
            args, close_fds=True,
            stdout=open(cwd("mitm.log", analysis=self.task.id), "wb"),
            stderr=open(cwd("mitm.err", analysis=self.task.id), "wb")
        )

        if "cert" in self.task.options:
            log.warning("A root certificate has been provided for this task, "
                        "however, this is overridden by the mitm auxiliary "
                        "module.")

        self.task.options["cert"] = certificate

        if "proxy" in self.task.options:
            log.warning("A proxy has been provided for this task, however, "
                        "this is overridden by the mitm auxiliary module.")

        # We are using the resultserver IP address as address for the host
        # where our mitmdump instance is running.
        if not transparent_mode:
            self.task.options["proxy"] = \
                "%s:%d" % (self.machine.resultserver_ip, port)
            log.info("Started mitm interception with PID %d (ip=%s, port=%d).",
                     self.proc.pid, self.machine.resultserver_ip, self.port)
        else:
            log.info("Started mitm transparent interception with PID %d (ip=%s, port=%d).",
                     self.proc.pid, self.machine.resultserver_ip, self.port)

        # Register listening port in option, to create iptables rules
        self.task.options["mitm_port"] = port

    def stop(self):
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

