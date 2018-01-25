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

class RamsomwareFileMoves(Signature):
    name = "ransomware_file_moves"
    description = "Performs %d file moves indicative of a ransomware file encryption process"
    severity = 3
    categories = ["ransomware"]
    minimum = "2.0"

    filter_apinames = "MoveFileWithProgressW", "MoveFileWithProgressTransactedW"

    count = 0

    def on_call(self, call, process):
        origfile = call["arguments"]["oldfilepath"]
        newfile = call["arguments"]["newfilepath"]
        if not origfile.endswith(".tmp") and not newfile.endswith(".tmp"):
            self.count += 1
            self.mark_call()

    def on_complete(self):
        if self.count > 50:
            self.description = self.description % self.count
            if self.has_marks(1000):
                self.severity = 6
            elif self.has_marks(500):
                self.severity = 5
            elif self.has_marks(100):
                self.severity = 4
            elif self.has_marks(50):
                self.severity = 3

            return self.has_marks()

class RansomwareAppendsExtension(Signature):
    name = "ransomware_appends_extensions"
    description = "Appends a new file extension or content to %d files indicative of a ransomware file encryption process"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "MoveFileWithProgressW", "MoveFileWithProgressTransactedW"

    count = 0

    def on_call(self, call, process):
        origfile = call["arguments"]["oldfilepath"]
        newfile = call["arguments"]["newfilepath"]
        if origfile != newfile and not origfile.endswith(".tmp") and not newfile.endswith(".tmp"):
            self.count += 1
            self.mark_call()

    def on_complete(self):
        if self.count > 50:
            self.description = self.description % self.count
            if self.has_marks(1000):
                self.severity = 6
            elif self.has_marks(500):
                self.severity = 5
            elif self.has_marks(100):
                self.severity = 4
            elif self.has_marks(50):
                self.severity = 3

            return self.has_marks()

from lib.cuckoo.common.abstracts import Signature

class RansomwareDroppedFiles(Signature):
    name = "ransomware_dropped_files"
    description = "Drops %d unknown file mime types indicative of ransomware writing encrypted files back to disk"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        count = 0

        for dropped in self.get_results("dropped", []):
            if "filepath" in dropped:
                droppedtype = dropped["type"]
                droppedname = dropped["name"]
                filepath = dropped["filepath"]
                if droppedtype == "data" and ".tmp" not in droppedname:
                    count += 1
                    self.mark_ioc("file", filepath)
        if count > 50:
            self.description = self.description % count
            if count > 1000:
                self.severity = 6
            elif count > 500:
                self.severity = 5
            elif count > 200:
                self.severity = 4
            return self.has_marks()

class OverwritesFiles(Signature):
    name = "overwites_files"
    description = "Overwrites %d files indicative of destructive file actions such as from ransomware"
    severity = 2
    families = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "NtCreateFile",

    count = 0

    def on_call(self, call, process):
        if call["arguments"]["create_disposition"] == 5:
            self.count += 1
            self.mark_call()

    def on_complete(self):
        if self.count > 50:
            self.description = self.description % self.count
            if self.count > 1000:
                self.severity = 6
            elif self.count > 500:
                self.severity = 5
            elif self.count > 200:
                self.severity = 4
            elif self.count > 100:
                self.severity = 3
            return self.has_marks()
