# Copyright (C) 2015 KillerInstinct, Accuvant, Inc. (bspengler@accuvant.com)
# Copyright (C) 2016 Cuckoo Foundation
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

class RansomwareFiles(Signature):
    name = "ransomware_files"
    description = "Creates known ransomware decryption instruction / key file."
    severity = 3
    categories = ["ransomware"]
    authors = ["KillerInstinct", "Cuckoo Technologies"]
    minimum = "2.0"

    indicators = [
        ".*\\\\help_decrypt\\.html$",
        ".*\\\\decrypt_instruction\\.html$",
        ".*\\\\decrypt_instructions\\.txt$",
        ".*\\\\vault\\.key$",
        ".*\\\\vault\\.txt$",
        ".*\\\\howto_restore_files\\.(txt|html|bmp|jpg|jpeg|png|lnk)$",
        ".*\\\\help_your_files\\.(png|html|txt)$",
        ".*\\\\read\\ me\\ for\\ decrypt\\.txt$",
        ".*\\\\your_files_are_encrypted\\.html$",
        ".*\\\\recovery\\+[a-z0-9]+\\.txt$",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
