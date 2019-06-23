# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

class CuckooError(Exception):
    pass

class CuckooPackageError(Exception):
    pass

class CuckooScreenshotError(Exception):
    pass

class CuckooFridaError(Exception):
    pass
