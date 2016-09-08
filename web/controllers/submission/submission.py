# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.files import Storage

from sflock import unpack

class SubmissionController:
    def __init__(self, submit_id):
        self.submit_id = submit_id

        self._path_root = ""
        self._files = []

        self.get_submit()

    def get_submit(self):
        db = Database()

        submit = db.view_submit(self.submit_id)
        tmp_path = submit.path

        self._files = os.listdir(tmp_path)
        self._path_root = submit.path

    def get_filetree(self):
        data = []

        for f in self._files:
            filename = Storage.get_filename_from_path(f)

            file_data = open("%s/%s" % (self._path_root, f), "rb")
            extracted = self.analyze_file(filename=filename,
                                          data=file_data.read())

            data.append(extracted)

        return data

    @staticmethod
    def analyze_file(filename, data, password=None):
        extracted = unpack(filepath=filename, contents=data, password=password)
        converted = extracted.astree()
        return converted

    def submit(self):
        pass

