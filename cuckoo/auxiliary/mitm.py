# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import threading
import yaml

from cuckoo.common.abstracts import Auxiliary
from cuckoo.misc import cwd, Popen

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
        script = cwd(self.options.get("script", "stuff/mitm.py"))
        certificate = self.options.get("certificate", "bin/cert.p12")
        conf = os.path.expanduser(self.options.get("conf", "~/.mitmproxy/config.yaml"))

        outpath = cwd("storage", "analyses", "%d" % self.task.id, "dump.mitm")

        if not os.path.exists(mitmdump):
            log.error("Mitmdump does not exist at path \"%s\", man in the "
                      "middle interception aborted.", mitmdump)
            return

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

        # Need at least the v3.0.0 of mitmproxy
        args = [
            mitmdump, "-q",
            "-s", '"{}" {}'.format(script, self.task.options.get("mitm", "")).strip(),
            "-p", "%d" % self.port,
            "--conf", "%s" % conf,
            "-w", outpath
        ]

        mitmlog = cwd("storage", "analyses", "%d" % self.task.id, "mitm.log")
        mitmerr = cwd("storage", "analyses", "%d" % self.task.id, "mitm.err")

        # Prepare the configuration for recovering TLS Master keys (useful for Wireshark)
        mitm_sslkeylogfile = cwd("storage", "analyses", "%d" % self.task.id, "mitm.sslkeylogfile")
        os.environ["MITMPROXY_SSLKEYLOGFILE"] = mitm_sslkeylogfile
        log.debug("TLS Master keys will be dropped in this file: "+mitm_sslkeylogfile)

        self.proc = Popen(
            args, close_fds=True,
            stdout=open(mitmlog, "wb"), stderr=open(mitmerr, "wb")
        )

        if "cert" in self.task.options:
            log.warning("A root certificate has been provided for this task, "
                        "however, this is overridden by the mitm auxiliary "
                        "module.")

        self.task.options["cert"] = certificate

        if "proxy" in self.task.options:
            log.warning("A proxy has been provided for this task, however, "
                        "this is overridden by the mitm auxiliary module.")

        # Load the configuration file and retrieve some information
        try:
            infile = ""
            with open(conf, "r") as infile:
                conf = yaml.safe_load(infile)
                
                if conf["mode"] == "regular":
                # We are using the resultserver IP address as address for the host
                # where our mitmdump instance is running. TODO Is this correct?
                    self.task.options["proxy"] = \
                        "%s:%d" % (self.machine.resultserver_ip, port)
            infile.close()

        except IOError:
            log.exception("Could not open %s" % conf)
        except ValueError:
            log.exception("Invalid YAML file %s" % conf)

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
