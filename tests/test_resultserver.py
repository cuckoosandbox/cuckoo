# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import tempfile

from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.resultserver import ResultHandler
from cuckoo.core.startup import init_logging
from cuckoo.main import cuckoo_create
from cuckoo.misc import mkdir, set_cwd, cwd

@mock.patch("cuckoo.core.resultserver.select")
def test_open_process_log_unicode(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    mkdir(cwd(analysis=1))
    mkdir(cwd("logs", analysis=1))

    request = server = mock.MagicMock()

    class Handler(ResultHandler):
        storagepath = cwd(analysis=1)

        def handle(self):
            pass

    init_logging(logging.DEBUG)

    try:
        task_log_start(1)
        Handler(request, (None, None), server).open_process_log({
            "pid": 1, "ppid": 2, "process_name": u"\u202e", "track": True,
        })
    finally:
        task_log_stop(1)
