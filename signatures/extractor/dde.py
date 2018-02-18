# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import xml.etree.ElementTree as ET

from cuckoo.common.abstracts import Extractor

ns = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}

def push_command_line(self, cmdline):
    if cmdline.startswith(("DDE ", "DDEAUTO ")):
        cmdline = cmdline.split(None, 1)[1]
    self.push_command_line(cmdline)

class OfficeDDE1(Extractor):
    yara_rules = "OfficeDDE1"
    minimum = "2.0.5"

    def handle_yara(self, filepath, match):
        root = ET.parse(filepath)

        elements = []
        for element in root.findall(".//w:instrText", ns):
            element.text and elements.append(element.text)

        push_command_line(self, "".join(elements).strip())

class OfficeDDE2(Extractor):
    yara_rules = "OfficeDDE2"
    minimum = "2.0.5"

    def handle_yara(self, filepath, match):
        root = ET.parse(filepath)

        for element in root.findall(".//w:fldSimple", ns):
            cmdline = element.get("{%s}instr" % ns["w"], "").strip()
            cmdline and push_command_line(self, cmdline)
