# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import tempfile
from nose.tools import assert_equals, raises

from lib.cuckoo.core.scheduler import AnalysisManager
from lib.cuckoo.core.startup import create_structure
from lib.cuckoo.common.abstracts import Dictionary
from lib.cuckoo.common.exceptions import CuckooAnalysisError
from lib.cuckoo.common.constants import CUCKOO_ROOT


class TestAnalysisManager:
    def setUp(self):
        create_structure()
        self.anal = Dictionary()
        self.anal["id"] = "test-cuckoo-remove-me"
        self.a = AnalysisManager(self.anal)

    def test_init_storage(self):
        self.a.init_storage()
        assert os.path.exists(self.a.analysis.results_folder)

    @raises(CuckooAnalysisError)
    def test_init_storage_error(self):
        self.a.analysis.results_folder = os.path.join(os.path.join(CUCKOO_ROOT, "storage", "analyses"), self.anal.id)
        os.mkdir(self.a.analysis.results_folder)
        self.a.init_storage()

    def test_store_file(self):
        file = tempfile.mkstemp()[1]
        self.anal["file_path"] = file
        self.a = AnalysisManager(self.anal)
        self.a.init_storage()
        self.a.store_file()
        bin_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", "d41d8cd98f00b204e9800998ecf8427e")
        assert_equals(bin_path, self.a.analysis.stored_file_path)
        assert os.path.exists(bin_path)
        os.remove(file)
        os.remove(bin_path)

    def tearDown(self):
        shutil.rmtree(self.a.analysis.results_folder)