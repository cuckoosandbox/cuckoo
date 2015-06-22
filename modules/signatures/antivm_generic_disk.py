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

class DiskInformation(Signature):
    name = "antivm_generic_disk"
    description = "Queries information on disks, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.signs = []

    def on_call(self, call, process):
        indicators = [
            "scsi0",
            "physicaldrive0"
        ]

        ioctls = [
            "2954240", # IOCTL_STORAGE_QUERY_PROPERTY
            "458752", # IOCTL_DISK_GET_DRIVE_GEOMETRY
            "315400" #IOCTL_SCSI_MINIPORT
        ]

        if process is not self.lastprocess:
            self.handle = None
            self.lastprocess = process
            self.signs = []

        if not self.handle:
            if call["api"] == "NtCreateFile":
                file_name = self.get_argument(call, "FileName")
                for indicator in indicators:
                    if indicator in file_name.lower():
                        self.handle = self.get_argument(call, "FileHandle")
                        self.signs.append(call)
        else:
            if call["api"] == "DeviceIoControl":
                if self.get_argument(call, "DeviceHandle") == self.handle:
                    if str(self.get_argument(call, "IoControlCode")) in ioctls:
                        self.signs.append(call)
                        self.add_match(process, 'api', self.signs)
                        return True
