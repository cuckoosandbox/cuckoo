# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
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

class VBoxDetectProvname(Signature):
    name = "antivm_vbox_provname"
    description = "Detects VirtualBox using WNetGetProviderName trick"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "2.0"
    evented = True

    filter_apinames = "WNetGetProviderNameW",

    def on_call(self, call, process):
        if call["arguments"]["net_type"] == "0x00250000":
            self.mark_call()

        return self.has_marks()
