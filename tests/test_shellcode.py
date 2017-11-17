# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest

from cuckoo.common.shellcode import Shellcode, shikata

class TestShikata(object):
    def setup(self):
        self.sc = Shellcode()

    def shikata(self, filename):
        return shikata(
            open("tests/files/shellcode/shikata/%s" % filename, "rb").read()
        )

    def test_unicorn100_good(self):
        assert self.shikata("1.bin").startswith("\xfc\xe8\x82")
        assert self.shikata("3.bin").startswith("\xfc\xe8\x82")
        assert self.shikata("4.bin").startswith("\xfc\xe8\x82")

    @pytest.mark.xfail
    def test_unicorn100_bad1(self):
        assert self.shikata("2.bin").startswith("\xfc\xe8\x82")

    @pytest.mark.xfail
    def test_unicorn100_bad2(self):
        assert self.shikata("5.bin").startswith("\xfc\xe8\x82")

    @pytest.mark.xfail
    def test_unicorn100_bad3(self):
        assert self.shikata("6.bin").startswith("\xfc\xe8\x82")

    def test_infinite_loop(self):
        assert shikata("\xeb\xfe") == "\xeb\xfe"
