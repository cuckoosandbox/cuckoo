# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
import tempfile

from cuckoo.common.config import Config
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.misc import set_cwd

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

class TestConfig:
    def setup(self):
        set_cwd(tempfile.mkdtemp())

        self.path = tempfile.mkstemp()[1]
        open(self.path, "wb").write(CONF_EXAMPLE)

        self.c = Config(cfg=self.path)

    def test_get_option_exist(self):
        """Fetch an option of each type from default config file."""
        assert self.c.get("cuckoo")["debug"] is False
        assert self.c.get("cuckoo")["tcpdump"] == "/usr/sbin/tcpdump"
        assert self.c.get("cuckoo")["critical_timeout"] == 600

    def test_config_file_not_found(self):
        assert Config("foo")

    def test_get_option_not_found(self):
        with pytest.raises(CuckooOperationalError):
            self.c.get("foo")

    def test_get_option_not_found_in_file_not_found(self):
        self.c = Config("bar")
        with pytest.raises(CuckooOperationalError):
            self.c.get("foo")
