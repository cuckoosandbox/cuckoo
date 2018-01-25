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
    minimum = "2.0"

    filter_apinames = [
        "NtCreateFile",
        "DeviceIoControl",
        "NtDeviceIoControlFile",
    ]

    indicators = [
        "scsi0",
        "physicaldrive0",
    ]

    ioctls = {
        2954240: "IOCTL_STORAGE_QUERY_PROPERTY",
        458752: "IOCTL_DISK_GET_DRIVE_GEOMETRY",
        315400: "IOCTL_SCSI_MINIPORT",
    }

    def init(self):
        self.drive_opened = False

    def on_call(self, call, process):
        if call["api"] == "NtCreateFile":
            filepath = call["arguments"]["filepath"].lower()
            if "scsi0" in filepath or "physicaldrive0" in filepath:
                self.drive_opened = True
                self.mark_call()

        if call["api"] in ["DeviceIoControl", "NtDeviceIoControlFile"]:
            if self.drive_opened and call["arguments"]["control_code"] in self.ioctls:
                self.mark_call()
                return True
