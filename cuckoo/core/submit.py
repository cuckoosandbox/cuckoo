# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import sflock

from cuckoo.common.config import Config
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common.utils import validate_url, validate_hash
from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.core.database import Database

log = logging.getLogger(__name__)

db = Database()

class SubmitManager(object):
    """Submit Manager.

    This class handles the submission process for files to be analyzed. It takes
    care of preparing the temporary storage locations, database registrations and
    interacting with the submitted files to determine a package.
    """
    def __init__(self):
        self._submit_urlschemes = ["http", "https"]

    def pre(self, submit_type, data):
        """
        The first step to submitting new analysis.
        @param submit_type: "files" or "strings"
        @param data: a list of dicts containing "name" (file name) and "data" (file data)
        or a list of strings (urls or hashes)
        @return: submit id
        """
        if submit_type not in ("strings", "files"):
            log.error("Bad parameter '%s' for submit_type", submit_type)
            return False

        path_tmp = Folders.create_temp()
        submit_data = {
            "data": [],
            "errors": []
        }

        if submit_type == "strings":
            for line in data:
                if not line:
                    continue

                if validate_hash(line):
                    try:
                        filedata = VirusTotalAPI(
                            Config("processing").virustotal.apikey,
                            Config("processing").virustotal.timeout
                        ).hash_fetch(line)
                    except CuckooOperationalError as e:
                        submit_data["errors"].append(
                            "Error retrieving file hash: %s" % e
                        )
                        continue

                    filepath = Files.create(path_tmp, line, filedata)

                    submit_data["data"].append({
                        "type": "file",
                        "data": filepath
                    })
                    continue

                if validate_url(line):
                    submit_data["data"].append({
                        "type": "url",
                        "data": line
                    })
                    continue

                submit_data["errors"].append(
                    "'%s' was neither a valid hash or url" % line
                )

        if submit_type == "files":
            for entry in data:
                filename = Storage.get_filename_from_path(entry["name"])
                filepath = Files.create(path_tmp, filename, entry["data"])
                submit_data["data"].append({
                    "type": "file",
                    "data": filepath
                })

        if not submit_data["data"]:
            raise Exception("Unknown submit type or no data could be processed")

        return Database().add_submit(path_tmp, submit_type, submit_data)

    @staticmethod
    def get_files(submit_id, password=None, astree=False):
        """
        Returns files from a submitted analysis.
        @param password: The password to unlock container archives with
        @param astree: sflock option; determines the format in which the files are returned
        @return: A tree of files
        """
        submit = Database().view_submit(submit_id)

        files, duplicates = [], []

        for data in submit.data["data"]:
            if data["type"] == "file":
                filename = Storage.get_filename_from_path(data["data"])
                filedata = open(os.path.join(submit.tmp_path, data["data"]), "rb").read()

                unpacked = sflock.unpack(
                    filepath=filename, contents=filedata,
                    password=password, duplicates=duplicates
                )

                if astree:
                    unpacked = unpacked.astree()

                files.append(unpacked)
            elif data["type"] == "url":
                files.append({
                    "filename": data["data"],
                    "filepath": "",
                    "relapath": "",
                    "selected": True,
                    "size": 0,
                    "type": "url",
                    "package": "ie",
                    "extrpath": [],
                    "duplicate": False,
                    "children": [],
                    "mime": "text/html",
                    "finger": {
                        "magic_human": "url",
                        "magic": "url"
                    }
                })
            else:
                continue

        return {
            "files": files,
            "path": submit.tmp_path,
        }

    @staticmethod
    def submit(submit_id, selected_files, timeout=0, package="", options="",
               priority=1, custom="", owner="", machine="", platform="",
               tags=None, memory=False, enforce_timeout=False, **kwargs):
        ret, db = [], Database()
        submit = db.view_submit(submit_id)

        for entry in selected_files:
            for expected in ["filepath", "filename", "type"]:
                if expected not in entry.keys() or not entry[expected]:
                    submit.data["errors"].append("")
                    continue

            if entry["type"] == "url":
                ret.append(db.add_url(
                    url=entry["filename"],
                    package="ie",
                    timeout=timeout,
                    options=options,
                    priority=int(priority),
                    custom=custom,
                    tags=tags,
                    memory=memory,
                    enforce_timeout=enforce_timeout,
                    machine=machine,
                    platform=platform,
                ))

                continue

            # for each selected file entry, create a new temp. folder
            path_dest = Folders.create_temp()

            if entry["filepath"][0] == "":
                path = os.path.join(
                    submit.tmp_path, os.path.basename(entry["filename"])
                )

                filename = entry["filename"]
                filepath = Files.copy(path, path_dest=path_dest)
            elif len(entry["filepath"]) >= 2:
                path = os.path.join(submit.tmp_path, os.path.basename(entry["filepath"][0]))
                path_extracted = os.path.join(
                    submit.tmp_path,
                    os.path.basename(entry["filepath"][-1])
                )

                content = sflock.unpack(path).read(entry["filepath"][1:])
                filename = entry["filepath"][-1]

                # Write extracted file to disk
                f = open(path_extracted, "wb")
                f.write(content)
                f.close()

                filepath = path_extracted
            else:
                submit.data["errors"].append("")
                continue

            if not package:
                package = entry.get("package", "")

            ret.append(db.add_path(
                file_path=filepath,
                package=package,  # user-defined package comes first, else let sflock decide
                timeout=timeout,
                options=options,
                priority=int(priority),
                custom=custom,
                tags=tags,
                memory=memory,
                enforce_timeout=enforce_timeout,
                machine=machine,
                platform=""
            ))

        return ret
