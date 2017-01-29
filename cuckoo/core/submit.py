# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import sflock

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
                        filedata = VirusTotalAPI().hash_fetch(line)
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
        # TODO Kwargs contains various analysis options that have to be taken
        # into account sooner or later.
        ret, db = [], Database()
        submit = db.view_submit(submit_id)

        for entry in selected_files:
            for expected in ["filepath", "filename", "type"]:
                if expected not in entry.keys() or not entry[expected]:
                    submit.data["errors"].append(
                        "Missing or empty argument %s" % expected
                    )
                    continue

            if entry["type"] == "url":
                ret.append(db.add_url(
                    url=entry["filename"],
                    package="ie",
                    timeout=timeout,
                    options=options,
                    priority=int(priority),
                    custom=custom,
                    owner=owner,
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

                filepath = Files.copy(path, path_dest=path_dest)

                ret.append(db.add_path(
                    file_path=filepath,
                    package=entry.get("package", package),
                    timeout=timeout,
                    options=options,
                    priority=int(priority),
                    custom=custom,
                    owner=owner,
                    tags=tags,
                    memory=memory,
                    enforce_timeout=enforce_timeout,
                    machine=machine,
                    platform=""
                ))
            elif len(entry["filepath"]) >= 2:
                arcpath = os.path.join(
                    submit.tmp_path, os.path.basename(entry["filepath"][0])
                )
                if not os.path.exists(arcpath):
                    submit.data["errors"].append(
                        "Unable to find parent archive file: %s" %
                        os.path.basename(entry["filepath"][0])
                    )
                    continue

                # Extract any sub-archives where required.
                if len(entry["filepath"]) > 2:
                    content = sflock.unpack(arcpath).read(
                        entry["filepath"][1:-1]
                    )
                else:
                    content = open(arcpath, "rb").read()

                # Write .zip archive file.
                filename = entry["filepath"][-2]
                arcpath = Files.temp_named_put(
                    sflock.zipify(sflock.unpack(filename, contents=content)),
                    os.path.basename(filename)
                )

                ret.append(db.add_archive(
                    file_path=arcpath,
                    filename=entry["filepath"][-1],
                    package=entry.get("package", package),
                    timeout=timeout,
                    options=options,
                    priority=int(priority),
                    custom=custom,
                    owner=owner,
                    tags=tags,
                    memory=memory,
                    enforce_timeout=enforce_timeout,
                    machine=machine,
                ))
            else:
                submit.data["errors"].append(
                    "Unable to determine type of file.. couldn't submit!"
                )
                continue

        return ret
