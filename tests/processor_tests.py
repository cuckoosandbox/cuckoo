# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.core.processor import Processor
from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.abstracts import Processing, Signature


class TestProcessor:
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = Processor(self.tmp)

    def test_run_processing(self):
        res = self.p._run_processing(ProcessingMock)
        assert "foo" in res
        assert "bar" in res["foo"]

    def test_run_signature(self):
        data = {"foo": "bar"}
        res = self.p._run_signature(SignatureMock, data)
        assert "name" in res
        assert_equals("mock", res["name"])

    def test_run_signature_alter_results(self):
        """@note: regression test."""
        res = {"foo": "bar"}
        self.p._run_signature(SignatureMock, res)
        assert_equals(res["foo"], "bar")
        
    def tearDown(self):
        os.rmdir(self.tmp)

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

class SignatureAlterMock(Signature):
    def run(self, results):
        results = None
        return True