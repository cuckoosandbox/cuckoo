#!/usr/bin/python
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
import sys
import time
import datetime

LOG_PATH_DEFAULT = "%s\\analysis.log" % os.getenv("SystemDrive")

# Get current timestamp.
def get_now(format = "%Y-%m-%d %H:%M:%S"):
    time = datetime.datetime.now()
    now = time.strftime(format)
    return now

# Log to analysis log file.
def log(message, level = "INFO", log_path = LOG_PATH_DEFAULT):
    if os.path.exists(log_path):
        log_file = open(log_path, "a")
    else:
        log_file = open(log_path, "w")

    if level:
        line = "[%s] [%s] %s\n" % (get_now(), level, message)
    else:
        line = "[%s] %s \n" % (get_now(), message)

    sys.stdout.write(line)
    log_file.write(line)
    log_file.close()
