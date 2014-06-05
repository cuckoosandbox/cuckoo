# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class Package(object):
    """Base abstact analysis package."""
    
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
        @param path: sample path.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def package_files(self):
        """
        A list of files to upload to host.
        The list should be a list of tuples (<path on guest>, <name of file in package_files folder>).
        (package_files is a folder that will be created in analysis folder). 
        """
        return None
    
    def finish(self):
        """Finish run.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError


class Auxiliary(object):
    pass
