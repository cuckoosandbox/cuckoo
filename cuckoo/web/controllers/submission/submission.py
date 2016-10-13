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
        # TODO: Example function that should be moved to Cuckoo core (remade too)
        ret, db = [], Database()
        submit = db.view_submit(self.submit_id)
        form_options = data["form"]

        for entry in data["selected_files"]:
            for expected in ["filepath", "filename", "package", "type"]:
                if not expected in entry.keys() or not entry[expected]:
                    # TODO Error logging.
                    continue

            # for each selected file entry, create a new temp. folder
            path_dest = Folders.create_temp()

            if entry["filepath"][0] == "":
                path = os.path.join(
                    submit.path, os.path.basename(entry["filename"])
                )

                # content = open(path, "rb").read()
                filename = entry["filename"]

                # Write to disk
                # Files.temp_named_put(content=content,
                #                      filename=filename,
                #                      path=submit.path)
                #
                # arcpath = Files.temp_named_put(
                #     zipify(unpack(filename, contents=content)),
                #     os.path.basename(filename)
                # )

                filepath = Files.copy(path, path_dest=path_dest)
            elif len(entry["filepath"]) >= 2:
                path = os.path.join(submit.path, os.path.basename(entry["filepath"][0]))
                path_extracted = os.path.join(
                    submit.path,
                    os.path.basename(entry["filepath"][-1])
                )

                content = unpack(path).read(entry["filepath"][1:])
                filename = entry["filepath"][-1]

                # Write extracted file to disk
                f = open(path_extracted, "wb")
                f.write(content)
                f.close()

                filepath = path_extracted
            else:
                # TODO Error logging.
                continue

            if data["form"]["package"]:
                package = data["form"]["package"]
            else:
                package = entry.get("package")

            ret.append(db.add_path(
                file_path=filepath,
                package=package,  # user-defined package comes first, else let sflock decide
                timeout=form_options["timeout"],
                options=form_options["options"],
                priority=int(form_options["priority"]),
                custom=form_options["custom"],
                tags=form_options["tags"],
                memory=form_options["memory"],
                enforce_timeout=form_options["enforce_timeout"],
                machine=form_options["machine"],
                platform="",  # what should this be?
            ))

        return ret
