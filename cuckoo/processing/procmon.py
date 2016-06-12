# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from lib.cuckoo.common.abstracts import Processing

try:
    import lxml.etree
    HAVE_LXML = True
except ImportError:
    HAVE_LXML = False

class ProcmonLog(list):
    """Yields each API call event to the parent handler."""

    def __init__(self, filepath):
        self.filepath = filepath

    def __iter__(self):
        procmon = open(self.filepath, "rb")
        for _, element in lxml.etree.iterparse(procmon, tag="event"):
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
