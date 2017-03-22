# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock

from modules.auxiliary.screenshots import Screenshots

@mock.patch("modules.auxiliary.screenshots.log")
@mock.patch("modules.auxiliary.screenshots.Screenshot")
def test_log_info(p, q):
    s = Screenshots()

    p.return_value.have_pil.return_value = False
    s.run()

    q.info.assert_called_once()
    q.warning.assert_not_called()
