# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import xml.etree.ElementTree

from cuckoo.common.abstracts import Processing

class ProcmonLog(list):
    """Yields each API call event to the parent handler."""

    def __init__(self, filepath):
        list.__init__(self)
        self.filepath = filepath

    def __iter__(self):
        iterator = xml.etree.ElementTree.iterparse(
            open(self.filepath, "rb"), events=["end"]
        )
        for _, element in iterator:
            if element.tag != "event":
                continue

            entry = {}
            for child in element.getchildren():
                entry[child.tag] = child.text
            yield entry

    def __nonzero__(self):
        # For documentation on this please refer to MonitorProcessLog.
        return True

class Procmon(Processing):
    """Extracts events from procmon.exe output."""

    key = "procmon"

    def run(self):
        procmon_xml = os.path.join(self.logs_path, "procmon.xml")
        if not os.path.exists(procmon_xml):
            return

        return ProcmonLog(procmon_xml)
