# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import egghatch
import logging
import os

from cuckoo.common.abstracts import Extractor
from cuckoo.common.objects import File, YaraMatch, Buffer
from cuckoo.common.scripting import Scripting
from cuckoo.common.utils import supported_version
from cuckoo.misc import cwd, version

log = logging.getLogger(__name__)

class ExtractManager(object):
    _instances = {}
    extractors = []

    @staticmethod
    def for_task(task_id):
        if task_id not in ExtractManager._instances:
            ExtractManager._instances[task_id] = ExtractManager(task_id)
        return ExtractManager._instances[task_id]

    def __init__(self, task_id):
        self.task_id = task_id
        self.items = []
        self.payloads = {}

    @classmethod
    def init_once(cls):
        cls.extractors = []

        # Gather all up-to-date Extractors. TODO Also handle nested subclasses.
        for ext in Extractor.__subclasses__():
            if not supported_version(version, ext.minimum, ext.maximum):
                log.debug(
                    "You are running a version of Cuckoo that's not "
                    "compatible with this Extractor (either it's too old or "
                    "too new): cuckoo=%s extractor=%s minversion=%s "
                    "maxversion=%s",
                    version, ext.__class__.__name__, ext.minimum, ext.maximum
                )
                continue

            cls.extractors.append(ext)

            # Turn str/unicode into a tuple of size one.
            if isinstance(ext.yara_rules, basestring):
                ext.yara_rules = ext.yara_rules,

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

    def push_command_line(self, cmdline):
        command = Scripting().parse_command(cmdline)
        if command and command.get_script():
            self.push_script(None, command)

    def push_script(self, process, command):
        filepath = self.write_extracted(
            command.ext, command.get_script().encode("utf8")
        )
        if not filepath:
            return

        process = process or {}

        yara_matches = File(filepath).get_yara("scripts")
        self.items.append({
            "category": "script",
            "program": command.program,
            "pid": process.get("pid"),
            "first_seen": process.get("first_seen"),
            "script": filepath,
            "yara": yara_matches,
        })
        for match in yara_matches:
            match = YaraMatch(match, "script")
            self.handle_yara(filepath, match)

    def push_script_recursive(self, command):
        self.push_script(None, command)
        for child in command.children:
            self.push_script_recursive(child)

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

    def push_blob(self, blob, category, externals, info=None):
        filepath = self.write_extracted("blob", blob)
        if not filepath:
            return

        yara_matches = File(filepath).get_yara(category, externals)

        self.items.append({
            "category": category,
            "raw": filepath,
            "yara": yara_matches,
            category: info,
        })
        for match in yara_matches:
            match = YaraMatch(match, category)
            self.handle_yara(filepath, match)

    def push_blob_noyara(self, blob, category, info=None):
        filepath = self.write_extracted("blob", blob)
        if not filepath:
            return

        self.items.append({
            "category": category,
            "raw": filepath,
            "yara": [],
            category: info,
        })

    def peek_office(self, files):
        for filename, content in files.items():
            externals = {
                "filename": filename,
            }
            if Buffer(content).get_yara_quick("office", externals):
                self.push_blob(content, "office", externals)

    def handle_yara(self, filepath, match):
        for plugin in self.extractors:
            if match.name in plugin.yara_rules:
                plugin(self).handle_yara(filepath, match)

    def results(self):
        # TODO Apply some sort of sorting here.
        return self.items
