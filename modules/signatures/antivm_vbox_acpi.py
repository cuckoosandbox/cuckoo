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

class VBoxDetectACPI(Signature):
    name = "antivm_vbox_acpi"
    description = "Detects VirtualBox using ACPI tricks"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.opened = False
            self.handle = None
            self.lastprocess = process
            self.signs = []

        # First I check if the malware opens the relevant registry key.
        if call["api"].startswith("RegOpenKeyEx"):
            # Check if the registry is HKEY_LOCAL_MACHINE.
            if (self.get_argument(call, "Registry") == "0x80000002"
            # Check if the subkey opened is the correct one.
            and self.get_argument(call, "SubKey")[:14].upper() == "HARDWARE\\ACPI\\"
            # Since it could appear under different paths, check for all of them.
            and self.get_argument(call, "SubKey")[14:18] in ["DSDT", "FADT", "RSDT"]):
                if self.get_argument(call, "SubKey")[18:] == "\\VBOX__":
                    self.add_match(process, 'api', call)
                else:
                    self.opened = True
                    self.handle = self.get_argument(call,"Handle")
                    self.signs.append(call)
        # Now I check if the malware verified the value of the key.
        elif call["api"].startswith("RegEnumKeyEx"):
            # Verify if the key was actually opened.
            if not self.opened:
                return

            # Verify the arguments.
            if (self.get_argument(call, "Handle") == self.handle
            and self.get_argument(call, "Name") == "VBOX__"):
                self.signs.append(call)
                self.add_match(process, 'api', self.signs)

    def on_complete(self):
        return self.has_matches()
