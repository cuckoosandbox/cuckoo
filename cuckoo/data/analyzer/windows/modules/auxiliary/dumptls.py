# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.api.process import Process
from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooError

log = logging.getLogger(__name__)

class DumpTLSMasterSecrets(Auxiliary):
    """Dump TLS master secrets as used by various Windows libraries."""
    def start(self):
        try:
            p = Process(process_name="lsass.exe")
            p.inject(track=False, mode="dumptls")
        except CuckooError as e:
            if "process access denied" in e.message:
                log.warning(
                    "You're not running the Cuckoo Agent as Administrator. "
                    "Doing so will improve your analysis results!"
                )
            else:
                log.warning(
                    "An unknown error occurred while trying to inject into "
                    "the lsass.exe process to dump TLS master secrets: %s", e
                )
