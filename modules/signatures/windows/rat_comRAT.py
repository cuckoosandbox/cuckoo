# Copyright (C) 2015 Robby Zeitfuchs (@robbyFux)
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

registry_indicator = "{DFFACDC5-679F-4156-8947-C5C76BC0B67F}\InprocServer32"

file_moves = [
    "Microsoft\\\\shdocvw.tlb",
    "Microsoft\\\\oleaut32.dll",
    "Microsoft\\\\oleaut32.tlb",
    "Microsoft\\\\credprov.tlb",
    "Microsoft\\\\libadcodec.dll",
    "Microsoft\\\\libadcodec.tlb",
]

class ComRAT(Signature):
    name = "rat_comRAT"
    description = "Turla-APT-Campaign: ComRAT"
    severity = 3
    alert = True
    categories = ["APT", "RAT"]
    families = ["Turla", "Uroburos", "Snake"]
    authors = ["Robby Zeitfuchs", "@robbyFux"]
    minimum = "2.0"

    references = [
        "https://blog.gdatasoftware.com/blog/article/the-uroburos-case-new-sophisticated-rat-identified.html",
        "https://malwr.com/analysis/NjJiODNlNjE4NjAwNDc3MGE4NmM1YzBmMzhlZjNiYTY/",
        "https://malwr.com/analysis/ZTE5MTMzODk1OGVkNDhiODg1ZDE3ZWM5MThjMmRiNjY/",
    ]

    filter_apinames = [
        "MoveFileWithProgressW",
        "NtWriteFile",
        "CreateProcessInternalW",
    ]

    def init(self):
        self.move_count = 0
        self.created_process = False
        self.wrote_pe_file = False

    def on_call(self, call, process):
        if call["api"] == "MoveFileWithProgressW":
            newfilepath = call["arguments"]["newfilepath"]
            if newfilepath.endswith(".tmp"):
                for filepath in file_moves:
                    oldfilepath = call["arguments"]["oldfilepath"]
                    if self._check_value(pattern=filepath,
                                         subject=oldfilepath,
                                         regex=True):
                        self.move_count += 1
                        self.mark_call()

        if call["api"] == "CreateProcessInternalW":
            # start rundll32.exe Install?
            if "rundll32.exe" in call["arguments"]["command_line"] and \
                    "Install" in call["arguments"]["command_line"]:
                self.created_process = True
                self.mark_call()

        if call["api"] == "NtWriteFile" and \
                call["arguments"]["buffer"][:2] == "MZ":
            self.wrote_pe_file = True
            self.mark_call()

    def on_complete(self):
        if not self.check_key(pattern=registry_indicator, regex=True):
            return

        if self.created_process and self.wrote_pe_file and \
                self.move_count == len(file_moves):
            return True
