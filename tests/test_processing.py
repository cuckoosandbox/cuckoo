# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile

from cuckoo.core.database import Database
from cuckoo.misc import set_cwd
from cuckoo.processing.debug import Debug

class TestProcessing:
    def test_debug(self):
        db = Database()

        set_cwd(tempfile.mkdtemp())

        db.connect(dsn="sqlite:///:memory:")
        db.add_url("http://google.com/")
        db.add_error("foo", 1)
        db.add_error("bar", 1)

        d = Debug()
        d.task = {
            "id": 1,
        }
        d.log_path = "nothing_to_see_here"
        d.cuckoolog_path = "neither here"
        d.action_path = "or here.."
        d.mitmerr_path = "no no no"

        results = d.run()
        assert len(list(results["errors"])) == len(results["errors"])
