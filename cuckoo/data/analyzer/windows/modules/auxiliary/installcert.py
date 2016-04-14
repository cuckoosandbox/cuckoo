# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import subprocess

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

class InstallCertificate(Auxiliary):
    """Install our man in the middle certificate into the Trusted Root
    Certification Authorities certificate store so we can listen in on https
    traffic."""
    def start(self):
        if "cert" not in self.options:
            return

        cert_path = self.options["cert"]

        if not cert_path.endswith(".p12"):
            log.error("An invalid certificate has been provided - only "
                      "PFX certificates, with file extension .p12, are "
                      "supported.")
            return

        if not os.path.exists(cert_path):
            log.error("Certificate file not found: %s. (Keep in mind that "
                      "the certificate must be located in the "
                      "analyzer/windows/ directory).", cert_path)
            return

        p = subprocess.Popen(["certutil.exe", "-importpfx", cert_path],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # Send an empty string as certutil expects to see a password for our
        # certificate on the command-line. Our certificate has no password.
        p.communicate("")

        log.info("Successfully installed PFX certificate.")
