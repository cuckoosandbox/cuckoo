# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.core.database import Database
from cuckoo.common.files import Storage

from sflock.abstracts import File
from sflock.unpack.zip import Zipfile
from sflock.unpack.rar import Rarfile
from sflock.unpack.tar import Tarfile

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
        duplicates = []

        for f in self._files:
            filename = Storage.get_filename_from_path(f)

            file_data = open("%s/%s" % (self._path_root, f), "rb")
            extracted = self.analyze_file(filename=filename,
                                          data=file_data.read(),
                                          duplicates=duplicates)

            duplicates.append(extracted.sha256)
            data.append(extracted)

        return data

    @staticmethod
    def analyze_file(filename, data, password=None, duplicates=None):
        if filename.endswith((".zip", ".gz", ".tar", ".tar.gz", ".bz2", ".tgz")):
            f = File(filepath=filename, contents=data)
            signature = f.get_signature()

            container = None
            if signature["family"] == "rar":
                container = Rarfile
            elif signature["family"] == "zip":
                container = Zipfile
            elif signature["family"] == "tar":
                container = Tarfile
            else:
                return f

            container = container(f=f)
            f.children = container.unpack(mode=signature["mode"],
                                          duplicates=duplicates)
            return f

        return File(filepath=filename, contents=data)

    def submit(self):
        pass
