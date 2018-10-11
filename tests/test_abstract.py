# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pytest
import tempfile

from cuckoo.common import abstracts

class TestProcessing(object):
    def setup(self):
        self.p = abstracts.Processing()

    def test_not_implemented_run(self):
        with pytest.raises(NotImplementedError):
            self.p.run()

class TestReport(object):
    def setup(self):
        self.r = abstracts.Report()

    def test_set_path(self):
        dir = tempfile.mkdtemp()
        rep_dir = os.path.join(dir, "reports")
        self.r.set_path(dir)
        assert os.path.exists(rep_dir)
        os.rmdir(rep_dir)

    def test_options_none(self):
        assert self.r.options is None

    def test_set_options_assignment(self):
        foo = {1: 2}
        self.r.set_options(foo)
        assert foo == self.r.options

    def test_not_implemented_run(self):
        with pytest.raises(NotImplementedError):
            self.r.run({})

class TestConfiguration(object):
    def test_simple(self):
        c = abstracts.Configuration()

        c.add({
            "family": "a", "url": "b", "type": "c",
        })
        assert c.results() == [{
            "family": "a", "url": ["b"], "type": "c",
        }]

        c.add({
            "family": "a", "url": ["d", None],
        })
        assert c.results() == [{
            "family": "a", "type": "c", "url": ["b", "d"],
        }]

        c.add({
            "family": "a", "version": 42,
        })
        assert c.results() == [{
            "family": "a", "type": "c", "version": 42, "url": ["b", "d"],
        }]

        c.add({
            "family": "b", "type": "c",
        })
        assert c.results() == [{
            "family": "a", "type": "c", "version": 42, "url": ["b", "d"],
        }, {
            "family": "b", "type": "c",
        }]

        c = abstracts.Configuration()
        c.add({
            "family": "a", "randomkey": "hello", "rc4key": "x",
        })
        assert c.results() == [{
            "family": "a",
            "key": {
                "rc4key": ["x"],
            },
            "extra": {
                "randomkey": ["hello"],
            }
        }]

        c.add({
            "family": "a", "rc4key": "x", "key": "y", "randomkey": "hello",
            "cnc": ["1", "2", ""],
        })
        assert c.results() == [{
            "family": "a",
            "key": {
                "rc4key": ["x"],
            },
            "cnc": ["1", "2"],
            "extra": {
                "randomkey": ["hello"],
                "key": ["y"],
            },
        }]
