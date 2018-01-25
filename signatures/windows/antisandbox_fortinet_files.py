# Copyright (C) 2016 Brad Spengler
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class FortinetDetectFiles(Signature):
    name = "antisandbox_fortinet_files"
    description = "Attempts to detect Fortinet Sandbox through the presence of a file"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Brad Spengler"]
    minimum = "2.0"

    files_re = [
        "C:\\\\tracer\\\\mdare32_0\\.sys",
        "C:\\\\tracer\\\\fortitracer\\.exe",
        "C:\\\\manual\\\\sunbox\\.exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        return self.has_marks()
