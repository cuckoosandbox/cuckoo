# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os.path
import shutil
import tempfile

from cuckoo.core.extract import ExtractManager
from cuckoo.core.startup import init_yara, init_modules
from cuckoo.misc import set_cwd, cwd, load_signatures
from cuckoo.processing.static import Static
from tests.utils import init_analysis

def task_id():
    task_id.current += 1
    return task_id.current

task_id.current = 0

def setup_module():
    set_cwd(tempfile.mktemp())
    shutil.copytree(os.path.expanduser("~/.cuckoo"), cwd())

def init(package, *filename):
    id_ = task_id()
    init_analysis(id_, package, *filename)
    load_signatures()
    init_modules()
    init_yara()

    s = Static()
    s.set_task({
        "id": id_,
        "category": "file",
        "package": package,
        "target": filename[-1],
    })
    s.file_path = cwd("binary", analysis=id_)
    e = ExtractManager.for_task(id_)
    return s.run(), e.results()

def test_docx_lnk():
    s, e = init("doc", "docx_lnk.doc_")
    assert s == {
        "office": {
            "macros": [],
            "eps": [],
        },
    }
    e1, e2, e3 = e
    assert e1["office"] == {}
    assert len(e1["yara"]) == 1
    assert e2["category"] == "binaries"
    assert e2["binaries"] == {
        "filename": " ",
        "src_path": mock.ANY,
        "temp_path": mock.ANY,
        "lnk": mock.ANY,
    }
    assert "http" in e2["binaries"]["lnk"]["cmdline"]
    assert len(e3["yara"]) == 1
    assert e3["yara"][0]["name"] == "PowershellDI"
