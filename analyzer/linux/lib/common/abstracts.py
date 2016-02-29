# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Package(object):
    """Base abstract analysis package."""
    PATHS = []

    def __init__(self, options={}):
        """@param options: options dict."""
        self.options = options
        self.pids = []

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def start(self):
        """Run analysis package.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        return True

    def execute(self, cmd):
        """Starts an executable for analysis.
        @param path: executable path
        @param args: executable arguments
        @return: process pid
        """
        p = Process()
        if not p.execute(cmd):
            raise CuckooPackageError("Unable to execute the initial process, "
                                     "analysis aborted.")

        return p.pid

    def package_files(self):
        """A list of files to upload to host.
        The list should be a list of tuples (<path on guest>, <name of file in package_files folder>).
        (package_files is a folder that will be created in analysis folder). 
        """
        return None
    
    def finish(self):
        """Finish run.
        If specified to do so, this method dumps the memory of
        all running processes.
        """
        if self.options.get("procmemdump"):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True

    def get_pids(self):
        return []

class Auxiliary(object):
    priority = 0

    def get_pids(self):
        return []
