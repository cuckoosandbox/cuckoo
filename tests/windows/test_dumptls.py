# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock

from lib.common.exceptions import CuckooError
from modules.auxiliary.dumptls import DumpTLSMasterSecrets

@mock.patch("modules.auxiliary.dumptls.Process")
@mock.patch("modules.auxiliary.dumptls.log")
def test_dumptls_regular_user(p, q):
    q.return_value.inject.side_effect = CuckooError(
        "Error returned by is32bit: process access denied"
    )
    DumpTLSMasterSecrets().start()
    p.warning.assert_called_once()
    assert "Agent as Administrator" in p.warning.call_args_list[0][0][0]

@mock.patch("modules.auxiliary.dumptls.Process")
@mock.patch("modules.auxiliary.dumptls.log")
def test_dumptls_success(p, q):
    DumpTLSMasterSecrets().start()
    p.warning.assert_not_called()
