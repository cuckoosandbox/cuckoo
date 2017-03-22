# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import subprocess
import time

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooDisableModule, CuckooPackageError
from lib.common.results import upload_to_host

class Procmon(Auxiliary):
    """Allow procmon to be run on the side."""
    def start(self):
        if not self.options.get("procmon"):
            raise CuckooDisableModule

        bin_path = os.path.join(self.analyzer.path, "bin")

        self.procmon_exe = os.path.join(bin_path, "procmon.exe")
        self.procmon_pmc = os.path.join(bin_path, "procmon.pmc")
        self.procmon_pml = os.path.join(bin_path, "procmon.pml")
        self.procmon_xml = os.path.join(bin_path, "procmon.xml")

        if not os.path.exists(self.procmon_exe) or \
                not os.path.exists(self.procmon_pmc):
            raise CuckooPackageError(
                "In order to use the Process Monitor functionality it is "
                "required to have Procmon setup with Cuckoo. Please run the "
                "Cuckoo Community script which will automatically fetch all "
                "related files to get you up-and-running."
            )

        # Start process monitor in the background.
        subprocess.Popen([
            self.procmon_exe,
            "/AcceptEula",
            "/Quiet",
            "/Minimized",
            "/BackingFile", self.procmon_pml,
        ])

        # Try to avoid race conditions by waiting until at least something
        # has been written to the log file.
        while not os.path.exists(self.procmon_pml) or \
                not os.path.getsize(self.procmon_pml):
            time.sleep(0.1)

    def stop(self):
        # Terminate process monitor.
        subprocess.check_call([
            self.procmon_exe,
            "/Terminate",
        ])

        # Convert the process monitor log into a readable XML file.
        subprocess.check_call([
            self.procmon_exe,
            "/OpenLog", self.procmon_pml,
            "/LoadConfig", self.procmon_pmc,
            "/SaveAs", self.procmon_xml,
            "/SaveApplyFilter",
        ])

        # Upload the XML file to the host.
        upload_to_host(self.procmon_xml, os.path.join("logs", "procmon.xml"))
