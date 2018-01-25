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

class AntiVMSCSI(Signature):
    name = "antivm_generic_scsi"
    description = "Detects virtualization software with SCSI Disk Identifier trick(s)"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\HARDWARE\\\\DEVICEMAP\\\\Scsi\\\\Scsi Port \\d+\\\\Scsi Bus \\d+\\\\Target Id \\d+\\\\Logical Unit Id \\d+\\\\Identifier",
        "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\Disk\\\\Enum\\\\.*",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
