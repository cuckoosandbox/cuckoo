# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class CuckooError(Exception):
    pass

class CuckooPackageError(Exception):
    pass

class CuckooDisableModule(CuckooError):
    """Exception for disabling a module dynamically."""
