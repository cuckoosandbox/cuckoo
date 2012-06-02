# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class Package(object):
    def __init__(self, options={}):
        self.options = options

    def run(self, path=None):
        raise NotImplementedError

    def check(self):
        raise NotImplementedError

    def finish(self):
        raise NotImplementedError
