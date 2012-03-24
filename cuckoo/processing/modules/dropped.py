# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os

from cuckoo.common.file import File
from cuckoo.processing.observers import Analysis

class Dropped(Analysis):
    def process(self):
        self.key = "dropped"

        dropped_files = []

        for file_name in os.listdir(self._dropped_path):
            file_path = os.path.join(self._dropped_path, file_name)

            if file_name == ".gitignore" and os.path.getsize(file_path) == 0:
                continue

            file_info = File(file_path).process()
            dropped_files.append(file_info)

        return dropped_files
