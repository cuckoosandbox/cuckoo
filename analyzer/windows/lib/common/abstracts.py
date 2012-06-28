# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class Package(object):
    """Base abstact analysis package."""
    
    def __init__(self, options={}):
        """@param options: options dict."""
        self.options = options

    def start(self, path=None):
        """Run analysis packege.
        @param path: sample path.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def finish(self):
        """Finish run.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError