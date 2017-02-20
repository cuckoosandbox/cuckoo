# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import logging
import os
import sflock

from cuckoo.common.config import emit_options
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common.utils import validate_url, validate_hash
from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.core.database import Database

log = logging.getLogger(__name__)

db = Database()

class SubmitManager(object):
    def _handle_string(self, submit, tmppath, line):
        if not line:
            return

        if validate_hash(line):
            try:
                filedata = VirusTotalAPI().hash_fetch(line)
            except CuckooOperationalError as e:
                submit["errors"].append(
                    "Error retrieving file hash: %s" % e
                )
                return

            filepath = Files.create(tmppath, line, filedata)

            submit["data"].append({
                "type": "file",
                "data": filepath
            })
            return

        if validate_url(line):
            submit["data"].append({
                "type": "url",
                "data": line
            })
            return

        submit["errors"].append(
            "'%s' was neither a valid hash or url" % line
        )

    def pre(self, submit_type, data):
        """
        The first step to submitting new analysis.
        @param submit_type: "files" or "strings"
        @param data: a list of dicts containing "name" (file name)
                and "data" (file data) or a list of strings (urls or hashes)
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
                self._handle_string(submit_data, path_tmp, line)

        if submit_type == "files":
            for entry in data:
                filename = Storage.get_filename_from_path(entry["name"])
                filepath = Files.create(path_tmp, filename, entry["data"])
                submit_data["data"].append({
                    "type": "file",
                    "data": filepath
                })

        return Database().add_submit(path_tmp, submit_type, submit_data)

    def get_files(self, submit_id, password=None, astree=False):
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
                filepath = os.path.join(submit.tmp_path, data["data"])
                filedata = open(filepath, "rb").read()

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
                raise RuntimeError(
                    "Unknown data entry type: %s" % data["type"]
                )

        return {
            "files": files,
            "path": submit.tmp_path,
        }

    def translate_options(self, info, options):
        """Translates Web Interface options to Cuckoo database options."""
        ret = {}

        if not int(options["simulated-human-interaction"]):
            ret["human"] = int(options["simulated-human-interaction"])

        return emit_options(ret)

    def submit(self, submit_id, config):
        """Reads, interprets, and converts the JSON configuration provided by
        the Web Interface into something we insert into the database."""
        ret = []
        submit = db.view_submit(submit_id)

        for entry in config["file_selection"]:
            # Merge the global & per-file analysis options.
            info = copy.deepcopy(config["global"])
            info.update(entry)
            options = copy.deepcopy(config["global"]["options"])
            options.update(entry.get("per_file_options", {}))

            kw = {
                "package": info.get("package"),
                "timeout": info.get("timeout", 120),
                "priority": info.get("priority"),
                "custom": info.get("custom"),
                "owner": info.get("owner"),
                "tags": info.get("tags"),
                "memory": info.get("memory"),
                "enforce_timeout": options.get("enforce-timeout"),
                "machine": info.get("machine"),
                "platform": info.get("platform"),
                "options": self.translate_options(info, options),
                "submit_id": submit_id,
            }

            if entry["type"] == "url":
                ret.append(db.add_url(
                    url=info["filename"], **kw
                ))
                continue

            # for each selected file entry, create a new temp. folder
            path_dest = Folders.create_temp()

            if not info["extrpath"]:
                path = os.path.join(
                    submit.tmp_path, os.path.basename(info["filename"])
                )

                filepath = Files.copy(path, path_dest=path_dest)

                ret.append(db.add_path(
                    file_path=filepath, **kw
                ))
            elif len(info["extrpath"]) == 1:
                arcpath = os.path.join(
                    submit.tmp_path, os.path.basename(info["arcname"])
                )
                if not os.path.exists(arcpath):
                    submit.data["errors"].append(
                        "Unable to find parent archive file: %s" %
                        os.path.basename(info["arcname"])
                    )
                    continue

                arc = sflock.zipify(sflock.unpack(
                    info["arcname"], contents=open(arcpath, "rb").read()
                ))

                # Create a .zip archive out of this container.
                arcpath = Files.temp_named_put(
                    arc, os.path.basename(info["arcname"])
                )

                ret.append(db.add_archive(
                    file_path=arcpath, filename=info["filename"], **kw
                ))
            else:
                arcpath = os.path.join(
                    submit.tmp_path, os.path.basename(info["arcname"])
                )
                if not os.path.exists(arcpath):
                    submit.data["errors"].append(
                        "Unable to find parent archive file: %s" %
                        os.path.basename(info["arcname"])
                    )
                    continue

                content = sflock.unpack(arcpath).read(info["extrpath"][:-1])
                subarc = sflock.unpack(info["extrpath"][-2], contents=content)

                # Write intermediate .zip archive file.
                arcpath = Files.temp_named_put(
                    sflock.zipify(subarc),
                    os.path.basename(info["extrpath"][-2])
                )

                ret.append(db.add_archive(
                    file_path=arcpath, filename=info["filename"], **kw
                ))

        return ret
