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

from cuckoo.common.file import File
from cuckoo.processing.observers import Analysis
from cuckoo.processing.modules.pe32.pe32 import PortableExecutable

class Static(Analysis):
    def process(self):
        self.key = "static"
        static = {}

        file_info = File(self._file_path).process()

        if "PE32" in file_info["type"]:
            static = PortableExecutable(self._file_path).process()

        return static
