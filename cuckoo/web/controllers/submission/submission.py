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

from sflock import unpack, zipify

class SubmissionController(object):
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

        if submit_type == "url":
            dirpath = Folders.create_temp()

            for line in data:
                if not line:
                    continue

                elif line.startswith("http://") or line.startswith("https://"):
                    # @TO-DO: analyse url
                    pass
                elif len(line) in (32, 40, 64, 128):
                    try:
                        if cfg.virustotal.key.type != "public":
                            if cfg.virustotal.key.type == "intelligence":
                                url = 'https://www.virustotal.com/intelligence/download/'
                            else:
                                url = "https://www.virustotal.com/vtapi/v2/file/download"

                            r = requests.get(url, params={
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

                    Files.create(dirpath, line, r.content)

            return db.add_submit(dirpath)

        raise Exception("Unknown submit type")

    def get_files(self, password=None, astree=False):
        submit = Database().view_submit(self.submit_id)

        files, duplicates = [], []

        for path in os.listdir(submit.path):
            filename = Storage.get_filename_from_path(path)
            filedata = open(os.path.join(submit.path, path), "rb").read()

            unpacked = unpack(
                filepath=filename, contents=filedata,
                password=password, duplicates=duplicates
            )
            if astree:
                unpacked = unpacked.astree()

            files.append(unpacked)

        return {
            "files": files,
            "path": submit.path,
        }

    def submit(self, data):
        ret, db = [], Database()
        submit = db.view_submit(self.submit_id)

        for entry in data["selected_files"]:
            # TODO Error logging.
            if not entry.get("filepath"):
                continue

            # Read the upper archive.
            arcpath = os.path.join(
                submit.path, os.path.basename(entry["filepath"][0])
            )

            # TODO Error logging.
            if not os.path.exists(arcpath):
                continue

            # Extract any sub-archives where required.
            if len(entry["filepath"]) > 2:
                content = unpack(arcpath).read(entry["filepath"][1:-1])
            else:
                content = open(arcpath, "rb").read()

            # Write .zip archive file.
            filename = entry["filepath"][-2]
            arcpath = Files.temp_named_put(
                zipify(unpack(filename, contents=content)),
                os.path.basename(entry["filepath"][-2])
            )

            ret.append(db.add_archive(
                file_path=arcpath,
                filename=entry["filepath"][-1],
                package=entry.get("package", data["form"]["package"]),
                timeout=data["form"]["timeout"],
                options=data["form"]["options"],
                priority=int(data["form"]["priority"]),
                custom=data["form"]["custom"],
                tags=data["form"]["tags"],
                memory=data["form"]["memory"],
                enforce_timeout=data["form"]["enforce_timeout"],
            ))

        return ret
