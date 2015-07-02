# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.api.process import Process
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

class DumpTLSMasterKeys(Auxiliary):
    """Dump TLS master keys as used by various Windows libraries."""
    def start(self):
        Process(process_name="lsass.exe").inject()
        log.info("Injected lsass for dumping TLS master keys!")
