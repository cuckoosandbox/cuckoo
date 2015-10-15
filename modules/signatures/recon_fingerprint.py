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

class Fingerprint(Signature):
    name = "recon_fingerprint"
    description = "Collects information to fingerprint the system (MachineGuid, DigitalProductId, SystemBiosDate)"
    severity = 3
    categories = ["recon"]
    authors = ["nex"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.threshold = 3
        self.matches = 0

    def on_call(self, call, process):
        indicators = [
            "MachineGuid",
            "DigitalProductId",
            "SystemBiosDate"
        ]

        if call["category"] != "registry":
            return

        for argument in call["arguments"]:
            for indicator in indicators:
                if argument["value"] == indicator:
                    self.add_match(process, 'api', call)
                    self.matches += 1


    def on_complete(self):
        return self.matches >= self.threshold
