# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import json
import mock
import os.path
import tempfile

from cuckoo.common.abstracts import Dictionary
from cuckoo.common.files import Folders
from cuckoo.core.log import task_log_stop
from cuckoo.core.scheduler import AnalysisManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd

def am_init(sha256_):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    class task(object):
        def __init__(self):
            self.id = 1234
            self.category = "file"
            self.target = __file__

        def to_dict(self):
            return Dictionary(self.__dict__)

        def to_json(self):
            return json.dumps(self.to_dict())

    class sample(object):
        sha256 = sha256_

    with mock.patch("cuckoo.core.scheduler.Database") as p:
        p.return_value.view_task.return_value = task()
        am = AnalysisManager(1234, None)

        p.return_value.view_sample.return_value = sample()

    return am

def test_am_init_success():
    sha256_ = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
    am = am_init(sha256_)

    assert am.init() is True
    assert os.path.exists(cwd(analysis=1234))
    assert os.path.exists(cwd("storage", "binaries", sha256_))
    assert os.path.exists(cwd("binary", analysis=1234))

    # Manually disable per-task logging initiated by init().
    task_log_stop(1234)

def test_am_init_duplicate_analysis():
    sha256_ = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
    am = am_init(sha256_)

    Folders.create(cwd(analysis=1234))
    assert am.init() is False

    # Manually disable per-task logging initiated by init().
    task_log_stop(1234)
