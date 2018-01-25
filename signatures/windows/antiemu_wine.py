# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class WineDetect(Signature):
    name = "antiemu_wine"
    description = "Detects the presence of Wine emulator"
    severity = 3
    categories = ["anti-emulation"]
    authors = ["nex"]
    minimum = "2.0"

    filter_apinames = "LdrGetProcedureAddress",

    indicators = [
        "HKEY_CURRENT_USER\\Software\\Wine",
    ]

    func_indicators = [
        "wine_get_version",
        "wine_nt_to_unix_file_name",
        "wine_get_unix_file_name",
        "wine_server_call",
    ]

    def on_call(self, call, process):
        if call["arguments"]["function_name"] in self.func_indicators:
            self.mark_call()

    def on_complete(self):
        for indicator in self.indicators:
            for regkey in self.check_key(pattern=indicator, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
