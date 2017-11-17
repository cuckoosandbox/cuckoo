# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import json
import logging
import os
import sflock
import zipfile

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common.utils import validate_url, validate_hash
from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.core.database import Database, TASK_COMPLETED
from cuckoo.misc import cwd, mkdir

log = logging.getLogger(__name__)
db = Database()

class SubmitManager(object):
    known_web_options = [
        "enable-injection", "enforce-timeout", "full-memory-dump",
        "process-memory-dump", "simulated-human-interaction",
    ]

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
                "data": validate_url(line),
            })
            return

        submit["errors"].append(
            "'%s' was neither a valid hash or url" % line
        )

    def translate_options_from(self, entry, options):
        """Translates from Web Interface options to Cuckoo database options."""
        ret = {}

        if not options.get("simulated-human-interaction", True):
            ret["human"] = int(options.get("simulated-human-interaction", True))

        if not options.get("enable-injection", True):
            ret["free"] = "yes"

        if options.get("process-memory-dump"):
            ret["procmemdump"] = "yes"

        # VPN takes precedence over the network-routing option (this should
        # actually be resolved in the frontend, though).
        if entry.get("vpn"):
            ret["route"] = entry["vpn"]
        elif entry.get("network-routing"):
            ret["route"] = entry["network-routing"]

        # Propagate any additional manually set key/value pairs.
        for key, value in options.items():
            if key not in self.known_web_options:
                ret[key] = value

        return ret

    def translate_options_to(self, options):
        """Translates from Cuckoo database options to Web Interface options."""
        ret = {}

        if not int(options.get("human", "1")):
            ret["simulated-human-interaction"] = False

        if options.get("free") == "yes":
            ret["enable-injection"] = False

        if options.get("procmemdump") == "yes":
            ret["process-memory-dump"] = True

        if options.get("route"):
            ret["network-routing"] = options["route"]

        return ret

    def pre(self, submit_type, data, options=None):
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
            "errors": [],
            "options": options or {},
        }

        if submit_type == "strings":
            for line in data:
                self._handle_string(submit_data, path_tmp, line.strip())

        if submit_type == "files":
            for entry in data:
                filename = Storage.get_filename_from_path(entry["name"])
                filepath = Files.create(path_tmp, filename, entry["data"])
                submit_data["data"].append({
                    "type": "file",
                    "data": filepath,
                    "options": self.translate_options_to(
                        entry.get("options", {})
                    ),
                })

        return db.add_submit(path_tmp, submit_type, submit_data)

    def get_files(self, submit_id, password=None, astree=False):
        """
        Returns files or URLs from a submitted analysis.
        @param password: The password to unlock container archives with
        @param astree: sflock option; determines the format in which the files are returned
        @return: A tree of files
        """
        submit = db.view_submit(submit_id)
        files, duplicates = [], []

        for data in submit.data["data"]:
            if data["type"] == "file":
                filename = Storage.get_filename_from_path(data["data"])
                filepath = os.path.join(submit.tmp_path, filename)

                unpacked = sflock.unpack(
                    filepath=filepath, password=password,
                    duplicates=duplicates
                )

                if astree:
                    unpacked = unpacked.astree(sanitize=True)

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

        return files, submit.data["errors"], submit.data["options"]

    def submit(self, submit_id, config):
        """Reads, interprets, and converts the JSON configuration provided by
        the Web Interface into something we insert into the database."""
        ret = []
        submit = db.view_submit(submit_id)

        machines = {}

        for entry in config["file_selection"]:
            # Merge the global & per-file analysis options.
            info = copy.deepcopy(config["global"])
            info.update(entry)
            info.update(entry.get("options", {}))
            options = copy.deepcopy(config["global"]["options"])
            options.update(entry.get("options", {}).get("options", {}))

            machine = info.get("machine")
            if machine:
                if machine not in machines:
                    m = db.view_machine(machine)
                    # TODO Add error handling for missing machine entry.
                    machines[machine] = m.label if m else None

                machine = machines[machine]
            else:
                machine = None

            kw = {
                "package": info.get("package"),
                "timeout": info.get("timeout", 120),
                "priority": info.get("priority"),
                "custom": info.get("custom"),
                "owner": info.get("owner"),
                "tags": info.get("tags"),
                "memory": options.get("full-memory-dump"),
                "enforce_timeout": options.get("enforce-timeout"),
                "machine": machine,
                "platform": info.get("platform"),
                "options": self.translate_options_from(info, options),
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
                    contents=open(arcpath, "rb").read(),
                    filename=info["arcname"]
                ))

                # Create a .zip archive out of this container.
                arcpath = Files.temp_named_put(
                    arc, os.path.basename(info["arcname"])
                )

                ret.append(db.add_archive(
                    file_path=arcpath, filename=info["relaname"], **kw
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
                subarc = sflock.unpack(
                    contents=content, filename=info["extrpath"][-2]
                )

                # Write intermediate .zip archive file.
                arcpath = Files.temp_named_put(
                    sflock.zipify(subarc),
                    os.path.basename(info["extrpath"][-2])
                )

                ret.append(db.add_archive(
                    file_path=arcpath, filename=info["relaname"], **kw
                ))

        return ret

    def import_(self, f, submit_id):
        """Import an analysis identified by the file(-like) object f."""
        try:
            z = zipfile.ZipFile(f)
        except zipfile.BadZipfile:
            raise CuckooOperationalError(
                "Imported analysis is not a proper .zip file."
            )

        # Ensure there are no files with illegal or potentially insecure names.
        # TODO Keep in mind that if we start to support other archive formats
        # (e.g., .tar) that those may also support symbolic links. In that case
        # we should probably start using sflock here.
        for filename in z.namelist():
            if filename.startswith("/") or ".." in filename or ":" in filename:
                raise CuckooOperationalError(
                    "The .zip file contains a file with a potentially "
                    "incorrect filename: %s" % filename
                )

        if "task.json" not in z.namelist():
            raise CuckooOperationalError(
                "The task.json file is required in order to be able to import "
                "an analysis! This file contains metadata about the analysis."
            )

        required_fields = {
            "options": dict, "route": basestring, "package": basestring,
            "target": basestring, "category": basestring, "memory": bool,
            "timeout": (int, long), "priority": (int, long),
            "custom": basestring, "tags": (tuple, list),
        }

        try:
            info = json.loads(z.read("task.json"))
            for key, type_ in required_fields.items():
                if key not in info:
                    raise ValueError("missing %s" % key)
                if info[key] is not None and not isinstance(info[key], type_):
                    raise ValueError("%s => %s" % (key, info[key]))
        except ValueError as e:
            raise CuckooOperationalError(
                "The provided task.json file, required for properly importing "
                "the analysis, is incorrect or incomplete (%s)." % e
            )

        if info["category"] == "url":
            task_id = db.add_url(
                url=info["target"], package=info["package"],
                timeout=info["timeout"], options=info["options"],
                priority=info["priority"], custom=info["custom"],
                memory=info["memory"], tags=info["tags"], submit_id=submit_id
            )
        else:
            # Users may have the "delete_bin_copy" enabled and in such cases
            # the binary file won't be included in the .zip file.
            if "binary" in z.namelist():
                filepath = Files.temp_named_put(
                    z.read("binary"), os.path.basename(info["target"])
                )
            else:
                filepath = __file__

            # We'll be updating the target shortly.
            task_id = db.add_path(
                file_path=filepath, package=info["package"],
                timeout=info["timeout"], options=info["options"],
                priority=info["priority"], custom=info["custom"],
                memory=info["memory"], tags=info["tags"], submit_id=submit_id
            )

        if not task_id:
            raise CuckooOperationalError(
                "There was an error creating a task for the to-be imported "
                "analysis in our database.. Can't proceed."
            )

        # The constructors currently don't accept this argument.
        db.set_route(task_id, info["route"])

        mkdir(cwd(analysis=task_id))
        z.extractall(cwd(analysis=task_id))

        # If there's an analysis.json file, load it up to figure out additional
        # metdata regarding this analysis.
        if os.path.exists(cwd("analysis.json", analysis=task_id)):
            try:
                obj = json.load(
                    open(cwd("analysis.json", analysis=task_id), "rb")
                )
                if not isinstance(obj, dict):
                    raise ValueError
                if "errors" in obj and not isinstance(obj["errors"], list):
                    raise ValueError
                if "action" in obj and not isinstance(obj["action"], list):
                    raise ValueError
            except ValueError:
                log.warning(
                    "An analysis.json file was provided, but wasn't a valid "
                    "JSON object/structure that we can to enhance the "
                    "analysis information."
                )
            else:
                for error in set(obj.get("errors", [])):
                    if isinstance(error, basestring):
                        db.add_error(error, task_id)
                for action in set(obj.get("action", [])):
                    if isinstance(action, basestring):
                        db.add_error("", task_id, action)

        # We set this analysis as completed so that it will be processed
        # automatically (assuming 'cuckoo process' is running).
        db.set_status(task_id, TASK_COMPLETED)
        return task_id
