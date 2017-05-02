# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.misc import cwd
from cuckoo.common.objects import File

class Extractor(object):
    _instances = {}

    @staticmethod
    def for_task(task_id):
        if task_id not in Extractor._instances:
            Extractor._instances[task_id] = Extractor(task_id)
        return Extractor._instances[task_id]

    def __init__(self, task_id):
        self.task_id = task_id
        self.items = []

    def __del__(self):
        del Extractor._instances[self.task_id]

    def push_script(self, process, command):
        dirpath = cwd("extracted", analysis=self.task_id)

        # TODO We need to move this somewhere else. Just a temporary
        # hack in case old reports are processed that don't have the
        # "extracted" directory in-place yet.
        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

        filepath = os.path.join(
            dirpath, "%d.%s" % (len(self.items), command.ext)
        )
        open(filepath, "wb").write(command.get_script().encode("utf8"))
        self.items.append({
            "category": "script",
            "program": command.program,
            "pid": process["pid"],
            "first_seen": process["first_seen"],
            "script": filepath,
            "yara": File(filepath).get_yara("scripts"),
        })

    def results(self):
        return sorted(self.items, key=lambda x: x["first_seen"])
