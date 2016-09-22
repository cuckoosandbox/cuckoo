# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import os
import requests

from cuckoo.core.database import Database
from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common.config import Config

from sflock import unpack

class SubmissionController:
    def __init__(self, submit_id=None):
        self.submit_id = submit_id

        self._path_root = ""
        self._files = []

    @staticmethod
    def presubmit(submit_type, data):
        """
        Register new file(s) for analysis into the database.
        @param submit_type: 'url' or 'files'
        @param data: if submit_type is 'files': a list of dicts containing 'name' (file name) and 'data' (file data)
        if submit_type is 'url': a list of strings containing either
        @return: presubmission id
        """
        cfg = Config("processing")
        db = Database()

        if submit_type == "files":
            dirpath = Folders.create_temp()

            for entry in data:
                filename = Storage.get_filename_from_path(entry["name"])
                Files.create(dirpath, filename, entry["data"])

            return db.add_submit(dirpath)
        elif submit_type == "url":
            files = []

            for line in data:
                if not line:
                    continue

                elif line.startswith("http://") or line.startswith("https://"):
                    # @TO-DO: analyse url
                    pass
                elif len(line) in (32, 40, 64, 128):
                    try:
                        r = requests.get("https://www.virustotal.com/vtapi/v2/file/download", params={
                            "apikey": cfg.virustotal.key,
                            "hash": line
                        })
                    except:
                        continue

                    if r.status_code != 200:
                        continue

                    name = "".join([c for c in line if re.match(r'\w', c)])
                    if not name:
                        continue

                    files.append({
                        "data": r.content,
                        "name": name
                    })

            if files:
                tmp_path = Files.tmp_put(files=files)
                return db.add_submit(tmp_path)

            return

        raise Exception("Unknown submit type")

    def get_files(self, password=None, astree=False):
        submit = Database().view_submit(self.submit_id)
        tmp_path = submit.path

        files = []

        for path in os.listdir(tmp_path):
            filename = Storage.get_filename_from_path(path)
            filedata = open("%s/%s" % (tmp_path, path), "rb").read()

            unpacked = unpack(filepath=filename, contents=filedata, password=password)
            if astree:
                unpacked = unpacked.astree()

            files.append(unpacked)

        return {
            "files": files,
            "path": submit.path,
        }

    def submit(self, data):
        return {}
