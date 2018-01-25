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

class DownloaderCabby(Signature):
    name = "downloader_cabby"
    description = "Suspicious downloader (Cabby)"
    severity = 3
    categories = ["downloader"]
    families = ["downloader"]
    authors = ["Robby Zeitfuchs"]
    minimum = "2.0"

    references = [
        "https://malwr.com/analysis/MmM0NDA5NWU5NjVmNDE5OGJmZmQ1MTdiZWVkMmU2ZDE/",
        "https://malwr.com/analysis/MmNmM2YxOWJhY2QxNDYyYTk3Y2IyNzI4NjQ0ZTEzOGY/",
    ]

    def on_complete(self):
        match_mutex = self.check_mutex(pattern=".*[0-9]{8}", regex=True)
        if match_mutex:
            self.mark_ioc("mutex", match_mutex)

        match_cab_file = self.check_file(pattern=".*\\\\Temp\\\\temp_cab_[0-9]*\.cab", regex=True)
        if match_cab_file:
            self.mark_ioc("file", match_cab_file)

        # TODO Does this really belong to the sample or is this just a generic
        # Windows 7 thing?
        match_connectivity_check = self.check_domain(pattern="windowsupdate.microsoft.com")
        if match_connectivity_check:
            self.mark_ioc("url", match_connectivity_check)

        return self.has_marks(3)
