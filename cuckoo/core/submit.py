# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import os
import logging
import requests

from cuckoo.core.database import Database, Submit
from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common.config import Config
from cuckoo.common.utils import validate_url, validate_hash

from sflock import unpack, zipify

log = logging.getLogger(__name__)

_cfg = Config("processing")
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
        global _cfg

        if not isinstance(submit_type, (str, unicode)) or \
                        submit_type not in ["strings", "files"]:
            log.error("Bad parameter \"%s\" for submit_type" % submit_type)
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

                try:
                    validate_url(line)
                    submit_data["data"].append({
                        "type": "url",
                        "data": line
                    })

                    continue
                except Exception as e:
                    pass

                try:
                    validate_hash(line)
                    filedata = VirusTotal(api_version="v2").fetch(file_hash=line)
                    filepath = Files.create(path_tmp, line, filedata)

                    submit_data["data"].append({
                        "type": "file",
                        "data": filepath
                    })
                    continue
                except Exception as e:
                    submit_data["errors"].append("\"%s\" was neither a valid hash or url" % line)
                    continue

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
        else:
            submit = Submit(tmp_path=path_tmp, submit_type=submit_type)
            submit.data = submit_data

            session = db.Session()

            session.add(submit)
            session.commit()

            return submit.id

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

    @staticmethod
    def submit(submit_id, selected_files, timeout=0, package="", options="",
               priority=1, custom="", owner="", machine="", platform="",
               tags=None, memory=False, enforce_timeout=False):
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


class VirusTotal:
    global _cfg

    def __init__(self, api_version="v2"):
        self._apikey = _cfg.virustotal.key
        self._version = {
            "v2": {
                "endpoint": "https://www.virustotal.com/vtapi/v2/file/download"
            }
        }[api_version]

    def fetch(self, file_hash):
        invalid_hash = re.search("[^\\w]+", file_hash)
        if invalid_hash:
            raise Exception("bad character \"%s\"" % invalid_hash.group(0))

        if self._version == "v2":
            resp = requests.get(self._version["endpoint"], timeout=60, params={
                "apikey": self._apikey,
                "hash": file_hash
            })
            if not resp.status_code == 200:
                raise Exception("Hash not found")
            #TODO check for content-type 'stream'
            return resp.content
