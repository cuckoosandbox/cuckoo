# Copyright (C) 2010-2015 Cuckoo Foundation. 2014 Optiv, Inc. (brad.spengler@optiv.com)
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

class VMWareDetectKeys(Signature):
    name = "antivm_vmware_keys"
    description = "Detects VMWare through the presence of a registry key"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies", "Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?VMWare,\\ Inc\..*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Clients\\\\StartMenuInternet\\\\VMWAREHOSTOPEN.EXE",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?\\\\Microsoft\\\\ESENT\\\\Process\\\\vmtoolsd",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\CriticalDeviceDatabase\\\\root#vmwvmcihostdev",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
