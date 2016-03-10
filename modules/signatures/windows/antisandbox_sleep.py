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

    def init(self):
        self.sleeps = []

    def on_call(self, call, process):
        sleep = call["arguments"]["milliseconds"]
        skip = call["arguments"]["skipped"]
        self.sleeps.append((process["process_name"], sleep, skip))

    def on_complete(self):
        proc_whitelist = [
            "dwm.exe",
            "adobearm.exe",
            "iexplore.exe",
            "acrord32.exe",
        ]
        procs = dict()
        for pname, sleep, skip in self.sleeps:
            if pname.lower() not in proc_whitelist:
                if pname not in procs:
                    procs[pname] = {
                        "attempted": 0,
                        "actual": 0,
                    }

                procs[pname]["attempted"] += sleep

                if not skip:
                    procs[pname]["actual"] += sleep

        for process_name, info in procs.items():
            if info["attempted"] >= 120000:
                actual = info["actual"] / 1000
                attempted = info["attempted"] / 1000
                self.mark(description="%s tried to sleep %s seconds, actually delayed analysis time by %s seconds" % (process_name, attempted, actual))

            if info["attempted"] >= 1200000:
                self.severity = 3
                self.mark(sleep_attempt=info["attempted"])

        return self.has_marks()
