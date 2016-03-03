# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.abstracts import Processing, Signature


class ProcessingMock(Processing):
    def run(self):
        self.key = "foo"
        foo = {
            "bar" : "taz"
        }
        return foo

class SignatureMock(Signature):
    name = "mock"
    minimum = CUCKOO_VERSION.split("-")[0]
    maximum = CUCKOO_VERSION.split("-")[0]

    def run(self, results):
        if "foo" in results:
            return True
        else:
            return False

class SignatureAlterMock(SignatureMock):
    def run(self, results):
        results = None

class SignatureDisabledMock(SignatureMock):
    enabled = False

class SignatureWrongVersionMock(SignatureMock):
    minimum = "0.0..-abc"
    maximum = "0.0..-abc"

