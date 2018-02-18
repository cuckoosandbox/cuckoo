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

class VPCDetectKeys(Signature):
    name = "antivm_vpc_keys"
    description = "Detects Virtual PC through the presence of a registry key"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\PCI\\\\VEN_5333&DEV_8811&SUBSYS_00000000&REV_00",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\vpc-s3",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
