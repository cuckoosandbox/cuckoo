# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import subprocess
import _winreg

from lib.common.abstracts import Auxiliary
from lib.common.registry import set_regkey
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

DebugPrintFilter = (
    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Debug Print Filter"
)

class DbgView(Auxiliary):
    """Run DbgView."""
    def start(self):
        if not self.options.get("dbgview"):
            return

        dbgview_path = os.path.join("bin", "dbgview.exe")
        if not os.path.exists(dbgview_path):
            log.error("DbgView.exe not found!")
            return

        # Make sure all logging makes it into DbgView.
        set_regkey(
            _winreg.HKEY_LOCAL_MACHINE, DebugPrintFilter,
            "", _winreg.REG_DWORD, 0xffffffff
        )

        self.filepath = os.path.join(self.analyzer.path, "bin", "dbgview.log")

        # Accept the EULA and enable Kernel Capture.
        subprocess.Popen([
            dbgview_path, "/accepteula", "/t", "/k", "/l", self.filepath,
        ])
        log.info("Successfully started DbgView.")

    def stop(self):
        upload_to_host(self.filepath, os.path.join("logs", "dbgview.log"))
