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

class TurlaCarbon(Signature):
    name = "apt_turlacarbon"
    description = "Appears to be the targeted Turla Carbon malware"
    severity = 3
    alert = True
    categories = ["apt"]
    families = ["turla", "uroburos", "snake"]
    authors = ["Robby Zeitfuchs", "@robbyFux"]
    minimum = "2.0"

    references = [
        "https://blog.gdatasoftware.com/blog/article/analysis-of-project-cobra.html",
        "https://malwr.com/analysis/MTI2M2RjYTAyZmNmNDE4ZTk5MDBkZjA4MDA5ZTFjMDc/",
    ]

    filter_apinames = "NtWriteFile",

    regkey_indicator = ".*\\\\ActiveComputerName$"
    buffer_indicators = [
        "[NAME]",
        "[TIME]",
        "iproc",
        "user_winmin",
        "user_winmax",
        "object_id",
    ]

    def init(self):
        self.wrote = False

    def on_call(self, call, process):
        # Check whether each buffer indicator is in this buffer write.
        for indicator in self.buffer_indicators:
            if indicator not in call["arguments"]["buffer"]:
                break
        else:
            self.wrote = True
            self.mark_call()

    def on_complete(self):
        if not self.check_key(self.regkey_indicator, regex=True):
            return

        if self.wrote:
            return True
