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

from cuckoo.core.now import *
from cuckoo.core.colors import *
from cuckoo.core.config import *

def log(message, level = "DEFAULT"):
    log_file = CuckooConfig().get_logging_path()
    level = level.upper()

    # If log level is "DEBUG", than just print message on screen.
    if level == "DEBUG":
         if CuckooConfig().get_logging_debug() == "True":
             line = "[%s] [DEBUG] %s\n" % (get_now(), message)
             sys.stdout.write(line)
    # Otherwise log message on file.
    else:
        if level == "WARNING" or level == "ERROR":
            line = "[%s] [%s] %s\n" % (get_now(), level, message)
        else:
            line = "[%s] %s\n" % (get_now(), message)

        if os.path.exists(log_file):
            log = open(log_file, "a")
        else:
            log = open(log_file, "w")

        log.write(line)
        log.close()

        if level == "WARNING":
            sys.stdout.write(yellow(line))
        elif level == "ERROR":
            sys.stdout.write(bold(red(line)))
        elif level == "INFO":
            sys.stdout.write(cyan(line))
        else:
            sys.stdout.write(line)

    return
