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

import os

CUCKOO_SETUP_SHARE = "\\\\VBOXSVR\\setup\\"
SYSTEM_SETUP_SRC = os.path.join(CUCKOO_SETUP_SHARE, "system\\")
CUCKOO_SETUP_SRC = os.path.join(CUCKOO_SETUP_SHARE, "cuckoo\\")

CUCKOO_PATH = "%s\\cuckoo\\" % os.getenv("SystemDrive")
CUCKOO_DLL_FOLDER = os.path.join(CUCKOO_PATH, "dll")
CUCKOO_DLL_PATH = os.path.join(CUCKOO_PATH, "dll\\cmonitor.dll")

CUCKOO_PIPE = "\\\\.\\pipe\\cuckoo"
