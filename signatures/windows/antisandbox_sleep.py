# Copyright (C) 2015 KillerInstinct
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

class AntiSandboxSleep(Signature):
    name = "antisandbox_sleep"
    description = "A process attempted to delay the analysis task."
    severity = 2
    categories = ["anti-sandbox"]
    authors = ["KillerInstinct"]
    minimum = "2.0"

    filter_apinames = "NtDelayExecution",

    whitelist = [
        "dwm.exe",
        "adobearm.exe",
        "iexplore.exe",
        "acrord32.exe",
        "winword.exe",
        "excel.exe",
    ]

    def init(self):
        self.sleeps = {}

    def on_call(self, call, process):
        procname = process["process_name"]
        if procname not in self.sleeps:
            self.sleeps[procname] = {
                "attempt": 0,
                "actual": 0,
            }

        milliseconds = call["arguments"]["milliseconds"]

        self.sleeps[procname]["attempt"] += milliseconds

        if not call["arguments"]["skipped"]:
            self.sleeps[procname]["actual"] += milliseconds

    def on_complete(self):
        for process_name, info in self.sleeps.items():
            if process_name.lower() in self.whitelist:
                continue

            if info["attempt"] >= 120000:
                attempted = info["attempt"] / 1000
                actual = info["actual"] / 1000
                self.mark(description="%s tried to sleep %s seconds, actually delayed analysis time by %s seconds" % (process_name, attempted, actual))

            if info["attempt"] >= 1200000:
                self.severity = 3

        return self.has_marks()
