# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.core.processor import Processor
from lib.cuckoo.common.abstracts import Processing, Signature


class TestProcessor:
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = Processor(self.tmp)

    def test_run_processor(self):
        res = {"a": "b"}
        tmp = self.p._run_processor(ProcessingMock, res)
        assert "foo" in res

    def test_run_processor_alter_results(self):
        """@note: regression test."""
        res = {"bar": "b"}
        self.p._run_processor(ProcessingMock, res)
        assert_equals(res["bar"], "b")

    def test_run_signature(self):
        res = {"foo": "bar"}
        sigs = []
        self.p._run_signature(SignatureMock, res, sigs)
        assert sigs

    def test_run_signature_alter_results(self):
        """@note: regression test."""
        res = {"foo": "bar"}
        sigs = []
        self.p._run_signature(SignatureMock, res, sigs)
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
    def run(self, results):
        if "foo" in results:
            return True
        else:
            return False

class SignatureAlterMock(Signature):
    def run(self, results):
        results = None
        return True