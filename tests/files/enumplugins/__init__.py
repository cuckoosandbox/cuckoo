# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from . import sig1, sig2, sig3

class meta:
    plugins = sig1.Sig1, sig2.Sig2, sig3.Sig3
