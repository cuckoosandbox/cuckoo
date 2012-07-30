# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permissi

from nose.tools import assert_equals
from lib.cuckoo.core.sniffer import Sniffer


class TestSniffer:
    def test_tcpdump_path_(self):
        assert_equals(Sniffer("foo").tcpdump, "foo")

    def test_tcpdump_not_found(self):
        assert_equals(False, Sniffer("foo").start())

    def test_interface_not_found(self):
        assert_equals(False, Sniffer("foo").start("ethfoo"))
