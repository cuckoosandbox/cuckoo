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

class AntiVMServices(Signature):
    name = "antivm_generic_services"
    description = "Enumerates services, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.sign = None

    def on_call(self, call, process):
        if call["api"].startswith("EnumServicesStatus"):
            self.add_match(process, 'api', call)
            return True
            
        if process is not self.lastprocess:
            self.handle = None
            self.lastprocess = process
            self.sign = None

        if not self.handle:
            if call["api"].startswith("RegOpenKeyEx"):
                if self.get_argument(call,"SubKey") == "SYSTEM\\ControlSet001\\Services":
                    self.handle = self.get_argument(call,"Handle")
                    self.sign = call
        else:
            if call["api"].startswith("RegEnumKeyEx"):
                if self.get_argument(call,"Handle") == self.handle:
                    self.add_match(process, 'api', self.sign)
                    self.handle = None
                    self.sign = None

    def on_complete(self):
        return self.has_matches()
