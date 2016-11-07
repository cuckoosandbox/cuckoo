# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from cuckoo.core.database import Database, Submit
from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common.config import Config
from cuckoo.common.utils import validate_url, validate_hash
from cuckoo.common.virustotal import VirusTotalAPI

from sflock import unpack

log = logging.getLogger(__name__)

_cfg = Config("processing")
db = Database()

class SubmitManager:
    """Submit Manager.

    This class handles the submission process for files to be analyzed. It takes
    care of preparing the temporary storage locations, database registrations and
    interacting with the submitted files to determine a package.
    """
    _submit_urlschemes = ["http", "https"]

    @staticmethod
    def pre(submit_type, files):
        """
        The first step to submitting new analysis.
        @param submit_type: "files" or "strings"
        @param files: a list of dicts containing "name" (file name) and "data" (file data)
        or a list of strings (urls OR hashes)
        @return: submit id
        """
        global _cfg

        if not isinstance(submit_type, (str, unicode)) or \
                        submit_type not in ["strings", "files"]:
            log.error("Bad parameter \"%s\" for submit_type" % submit_type)
            return

        path_tmp = Folders.create_temp()
        data = {"data": [], "errors": []}

        if submit_type == "strings":
            for line in files:
                if not line:
                    continue

                try:
                    _url = validate_url(line, schemes=self._submit_urlschemes)
                    _hash = validate_hash(line)

                    if _url:
                        data["data"].append({
                            "type": "url",
                            "data": line
                        })

                        continue
                    elif _hash:
                        vt = _cfg.get("virustotal")
                        vt_api_key = vt["key"]
                        vt_timeout = vt["timeout"]
                        vt_scan = vt["scan"]

                        vt_api = VirusTotalAPI(
                            apikey=vt_api_key,
                            timeout=vt_timeout,
                            scan=vt_scan
                        )

                        file_data = vt_api.hash_fetch(file_hash=_hash)
                        file_path = Files.create(path_tmp, _hash, file_data)

                        data["data"].append({
                            "type": "file",
                            "data": file_path
                        })

                        continue
                    else:
                        raise Exception("neither a valid url or hash")
                except Exception as e:
                    data["errors"].append("\"%s\" could not be processed: %s" % (line, str(e)))
                    continue

        if submit_type == "files":
            for entry in files:
                file_name = Storage.get_filename_from_path(entry["name"])
                file_path = Files.create(path_tmp, file_name, entry["data"])

                data["data"].append({
                    "type": "file",
                    "data": file_path
                })

        if not data["data"]:
            data["errors"].insert(0, "None of the submitted data could be processed")

        submit = Submit(tmp_path=path_tmp, submit_type=submit_type)
        submit.data = data

        session = db.Session()
        session.add(submit)
        session.commit()

        return submit.id

    @staticmethod
    def pre_submit(submit_id, selected_files, timeout=0, package="", options="",
                   priority=1, custom="", owner="", machine="", platform="",
                   tags=None, memory=False, enforce_timeout=False, **kwargs):
        """Creates tasks, returns a list of `Task` id's"""
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

                content = unpack(path).read(entry["filepath"][1:])
                filename = entry["filepath"][-1]

                # Write extracted file to disk
                f = open(path_extracted, "wb")
                f.write(content)
                f.close()

                filepath = path_extracted
            else:
                submit.data["errors"].append("")
                continue

            # let sflock decide the package if option 'package' is set to 'automatically detect'
            if package:
                _package = package
            else:
                _package = entry.get("package", "")

            ret.append(db.add_path(
                file_path=filepath,
                package=_package,
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

    @staticmethod
    def submit(data):
        """
        Automatic file submission
        @param data: a list of dicts containing "name" (file name) and "data" (file data)
        or a list of strings (urls OR hashes)
        """
        if not data:
            raise Exception("parameter data missing")
        if not isinstance(data, list):
            raise Exception("parameter data should be a list")
        if isinstance(data[0], (unicode, str)):
            submit_type = "strings"
        elif isinstance(data[0], dict):
            submit_type = "files"
        else:
            raise Exception("paramter data has an invalid format")

        submit_id = SubmitManager.pre(submit_type=submit_type, files=data)
        files = SubmitManager.get_files(submit_id=submit_id, astree=True)
        path = files["path"]

        # fill selected_files in such way that calling the functionworks
        SubmitManager.pre_submit(
            submit_id=submit_id,
            selected_files=""
        )

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

                unpacked = unpack(
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