# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import subprocess
import threading

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)
PORTS = []
PORT_LOCK = threading.Lock()

class MITM(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None

    def start(self):
        mitmdump = self.options.get("mitmdump", "/usr/local/bin/mitmdump")
        port_base = int(self.options.get("port_base", 50000))
        script = self.options.get("script", "data/mitm.py")
        certificate = self.options.get("certificate", "bin/cert.p12")

        outpath = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                               "%d" % self.task.id, "dump.mitm")

        if not os.path.exists(mitmdump):
            log.error("Mitmdump does not exist at path \"%s\", man in the "
                      "middle interception aborted.", mitmdump)
            return

        if not os.path.exists(script):
            log.error("Mitmdump script file does not exist at path \"%s\", "
                      "man in the middle interception aborted.", script)
            return

        cert_path = os.path.join("analyzer", "windows", certificate)
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

        args = [
            mitmdump, "-q",
            "-s", "\"%s\" %s" % (script, self.task.options.get("mitm", "")),
            "-p", "%d" % self.port,
            "-w", outpath
        ]

        mitmlog = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                               "%d" % self.task.id, "mitm.log")

        mitmerr = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                               "%d" % self.task.id, "mitm.err")

        self.proc = subprocess.Popen(args,
                                     stdout=open(mitmlog, "wb"),
                                     stderr=open(mitmerr, "wb"))

        if "cert" in self.task.options:
            log.warning("A root certificate has been provided for this task, "
                        "however, this is overridden by the mitm auxiliary "
                        "module.")

        self.task.options["cert"] = certificate

        if "proxy" in self.task.options:
            log.warning("A proxy has been provided for this task, however, "
                        "this is overridden by the mitm auxiliary module.")

        # We are using the resultserver IP address as address for the host
        # where our mitmdump instance is running. TODO Is this correct?
        self.task.options["proxy"] = \
            "%s:%d" % (self.machine.resultserver_ip, port)

        log.info("Started mitm interception with PID %d (ip=%s, port=%d).",
                 self.proc.pid, self.machine.resultserver_ip, self.port)

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
