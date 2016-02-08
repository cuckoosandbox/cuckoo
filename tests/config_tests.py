# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile
from nose.tools import assert_equals, raises

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooOperationalError


class TestConfig:
    CONF_EXAMPLE = """
[cuckoo]
debug = off
analysis_timeout = 120
critical_timeout = 600
delete_original = off
machine_manager = kvm
use_sniffer = no
tcpdump = /usr/sbin/tcpdump
interface = vboxnet0
"""

    def setUp(self):
        self.path = tempfile.mkstemp()[1]
        self._load_conf(self.CONF_EXAMPLE)
        self.c = Config(cfg=self.path)

    def _load_conf(self, conf):
        """Loads a configuration from a string.
        @param conf: configuration string.
        """
        f = open(self.path, "w")
        f.write(conf)
        f.close()

    def test_get_option_exist(self):
        """Fetch an option of each type from default config file."""
        assert_equals(self.c.get("cuckoo")["debug"], False)
        assert_equals(self.c.get("cuckoo")["tcpdump"], "/usr/sbin/tcpdump")
        assert_equals(self.c.get("cuckoo")["critical_timeout"], 600)

    def test_config_file_not_found(self):
        assert Config("foo")

    @raises(CuckooOperationalError)
    def test_get_option_not_found(self):
        self.c.get("foo")

    @raises(CuckooOperationalError)
    def test_get_option_not_found_in_file_not_found(self):
        self.c = Config("bar")
        self.c.get("foo")
