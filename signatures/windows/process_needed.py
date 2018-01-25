# Copyright (C) 2015 Optiv Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
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

class ProcessNeeded(Signature):
    name = "process_needed"
    description = "Repeatedly searches for a not-found process, you may want to run a web browser during analysis"
    severity = 2
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.searches = 0
        self.did_openprocess = 0

    filter_apinames = "Process32NextW", "NtOpenProcess"

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if not call["status"]:
                if self.did_openprocess:
                    self.did_openprocess = 0
                else:
                    self.searches += 1
                    self.mark_call()
        else:
            # is NtOpenProcess
            self.did_openprocess = 1

    def on_complete(self):
        if self.searches > 5:
            return self.has_marks()
