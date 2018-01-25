# Copyright (C) 2016 Kevin Ross
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

class AntiVMComputernameQuery(Signature):
    name = "antivm_queries_computername"
    description = "Queries for the computername"
    severity = 1
    categories = ["AntiVM"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "GetComputerNameA",
        "GetComputerNameW",
        "GetComputerNameExA",
        "GetComputerNameExW",
    ]
    
    whitelistprocs = [
        "iexplore.exe",
        "firefox.exe",
        "chrome.exe",
        "safari.exe",
        "acrord32.exe",
        "acrord64.exe",
        "wordview.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "mspub.exe"
    ]

    def on_call(self, call, process):
        if process["process_name"].lower() not in self.whitelistprocs:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
