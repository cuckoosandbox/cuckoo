# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class HTML(Package):
    """HTML file analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        dll = self.options.get("dll", None)
        suspended = True
        if free:
            suspended = False

        if os.getenv("ProgramFiles(x86)"):
            iex86 = os.path.join(os.getenv("ProgramFiles(x86)"), "Internet Explorer", "iexplore.exe")
        else:
            iex86 = os.path.join(os.getenv("ProgramFiles"), "Internet Explorer", "iexplore.exe")

        ie32 = os.path.join(os.getenv("ProgramFiles"), "Internet Explorer", "iexplore.exe")
        
        if os.path.exists(iex86):
            iexplore = iex86
        else:
            iexplore = ie32

        # Travelling inside malware universe you should bring a towel with you.
        # If a file detected as HTML is submitted without a proper extension,
        # or without an extension at all (are you used to name samples with hash?),
        # IE is going to open it as a text file, so you precious sample will not
        # be executed.
        # We help you sample to execute renaming it with a proper extension.
        if not path.endswith(".html") or not path.endswith(".htm"):
            shutil.copy(path, path + ".html")
            path = path + ".html"
            log.info("Submitted file is missing extension, adding .html")

        p = Process()
        if not p.execute(path=iexplore, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet "
                                     "Explorer process, analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
