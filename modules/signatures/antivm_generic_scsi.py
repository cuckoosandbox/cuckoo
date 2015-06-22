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
    description = "Detects virtualization software with SCSI Disk Identifier trick"
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
        indicator_registry = "0x80000002"
        indicator_key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
        indicator_name = "Identifier"

        if process is not self.lastprocess:
            self.handle = ""
            self.opened = False
            self.lastprocess = process

        # First I check if the malware opens the releavant registry key.
        if call["api"].startswith("RegOpenKeyEx"):
            # Store the number of arguments matched.
            args_matched = 0
            # Store the handle used to open the key.
            self.handle = ""
            # Check if the registry is HKEY_LOCAL_MACHINE.
            if self.get_argument(call,"Registry") == indicator_registry:
                args_matched += 1
            # Check if the subkey opened is the correct one.
            if self.get_argument(call,"SubKey") == indicator_key:
                args_matched += 1

            # If both arguments are matched, I consider the key to be successfully opened.
            if args_matched == 2:
                self.opened = True
                # Store the generated handle.
                self.handle = self.get_argument(call,"Handle")
                # Store the API call in the signs
                self.signs.append(call)
        # Now I check if the malware verified the value of the key.
        if call["api"].startswith("RegQueryValueEx"):
            # Verify if the key was actually opened.
            if not self.opened:
                return

            # Verify the arguments.
            args_matched = 0
            if self.get_argument(call,"Handle") == self.handle:
                args_matched += 1
            if self.get_argument(call,"ValueName") == indicator_name:
                args_matched += 1

            # Finally, if everything went well, I consider the signature as matched.
            if args_matched == 2:
                # Store the API call in the signs
                self.signs.append(call)
                self.add_match(process, 'api', self.signs)
                return True
