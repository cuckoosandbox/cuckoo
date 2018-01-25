# Copyright (C) 2017 Kevin Ross
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

class CreatesShortcut(Signature):
    name = "creates_shortcut"
    description = "Creates a shortcut to an executable file"
    severity = 2
    categories = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    files_re = [
        ".*\.lnk$",
    ]

    whitelist = [
        "C:\Users\Administrator\AppData\Local\Temp\%ProgramData%\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell\Windows PowerShell.lnk",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell\Windows PowerShell.lnk",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                if match in self.whitelist:
                    continue

                self.mark_ioc("file", match)

        return self.has_marks()
