# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shutil
import logging

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class HTML(Package):
    """HTML file analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, path):
        iexplore = self.get_path("browser")
        free = self.options.get("free")
        dll = self.options.get("dll")
        suspended = True
        if free:
            suspended = False

        # Travelling inside malware universe you should bring a towel with you.
        # If a file detected as HTML is submitted without a proper extension,
        # or without an extension at all (are you used to name samples with hash?),
        # IE is going to open it as a text file, so your precious sample will not
        # be executed.
        # We help you sample to execute renaming it with a proper extension.
        if not path.endswith((".htm", ".html")):
            shutil.copy(path, path + ".html")
            path = path + ".html"
            log.info("Submitted file is missing extension, adding .html")

        p = Process()
        if not p.execute(path=iexplore, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet "
                                     "Explorer process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
