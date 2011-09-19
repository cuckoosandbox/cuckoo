# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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

import re
import os

from cuckoo.core.logging import *

def get_filetype(file_path):
    if not os.path.exists(file_path):
        log("[Get File Type] Cannot find file at path \"%s\"." % file_path,
            "ERROR")
        return None

    data = open(file_path, "rb").read()

    if re.match("MZ", data):
        return "exe"
    elif re.match("%PDF", data):
        return "pdf"
    else:
        return "Not supported"
