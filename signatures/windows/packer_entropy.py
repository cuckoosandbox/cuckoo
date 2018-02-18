# Copyright (C) 2014 Robby Zeitfuchs (@robbyFux)
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

class PackerEntropy(Signature):
    name = "packer_entropy"
    description = "The binary likely contains encrypted or compressed data indicative of a packer"
    severity = 2
    categories = ["packer"]
    authors = ["Robby Zeitfuchs", "nex"]
    minimum = "2.0"
    references = [
        "http://www.forensickb.com/2013/03/file-entropy-explained.html",
        "http://virii.es/U/Using%20Entropy%20Analysis%20to%20Find%20Encrypted%20and%20Packed%20Malware.pdf",
    ]

    def on_complete(self):
        total_compressed, total_pe_data = 0, 0

        for section in self.get_results("static", {}).get("pe_sections", []):
            total_pe_data += int(section["size_of_data"], 16)

            if float(section["entropy"]) > 6.8:
                self.mark(section=section, entropy=section["entropy"],
                          description="A section with a high entropy has been found")
                total_compressed += int(section["size_of_data"], 16)

        if total_pe_data and float(total_compressed) / total_pe_data > .2:
            self.mark(entropy=float(total_compressed) / total_pe_data,
                      description="Overall entropy of this PE file is high")
                      
        return self.has_marks()

