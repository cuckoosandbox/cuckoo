# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import egghatch
import os

from cuckoo.common.abstracts import Extractor
from cuckoo.common.objects import File, YaraMatch
from cuckoo.misc import cwd

class ExtractManager(object):
    _instances = {}

    @staticmethod
    def for_task(task_id):
        if task_id not in ExtractManager._instances:
            ExtractManager._instances[task_id] = ExtractManager(task_id)
        return ExtractManager._instances[task_id]

    def __init__(self, task_id):
        self.task_id = task_id
        self.items = []
        self.payloads = {}

    def __del__(self):
        del ExtractManager._instances[self.task_id]

    def write_extracted(self, ext, payload):
        dirpath = cwd("extracted", analysis=self.task_id)

        # TODO We need to move this somewhere else. Just a temporary
        # hack in case old reports are processed that don't have the
        # "extracted" directory in-place yet.
        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

        # Handle duplicate payloads.
        if payload in self.payloads:
            return

        self.payloads[payload] = True

        # TODO Implement some rate-limiting here.

        filepath = os.path.join(dirpath, "%d.%s" % (len(self.items), ext))
        open(filepath, "wb").write(payload)
        return filepath

    def push_script(self, process, command):
        filepath = self.write_extracted(
            command.ext, command.get_script().encode("utf8")
        )
        if not filepath:
            return

        yara_matches = File(filepath).get_yara("scripts")
        self.items.append({
            "category": "script",
            "program": command.program,
            "pid": process["pid"],
            "first_seen": process["first_seen"],
            "script": filepath,
            "yara": yara_matches,
        })
        for match in yara_matches:
            match = YaraMatch(match, "script")
            self.handle_yara(filepath, match)

    def push_shellcode(self, sc):
        filepath = self.write_extracted("bin", sc)
        if not filepath:
            return

        # This file contains a plaintext representation of the shellcode.
        open("%s.txt" % filepath, "wb").write(egghatch.as_text(sc))

        yara_matches = File(filepath).get_yara("shellcode")
        self.items.append({
            "category": "shellcode",
            "raw": filepath,
            "shellcode": "%s.txt" % filepath,
            "yara": yara_matches,
        })
        for match in yara_matches:
            match = YaraMatch(match, "shellcode")
            self.handle_yara(filepath, match)

    def handle_yara(self, filepath, match):
        # TODO Also handle nested subclasses.
        for plugin in Extractor.__subclasses__():
            # TODO Handle both str & tuple/list properly.
            if match.name in plugin.yara_rules:
                plugin(self).handle_yara(filepath, match)

    def results(self):
        # TODO Apply some sort of sorting here.
        return self.items
