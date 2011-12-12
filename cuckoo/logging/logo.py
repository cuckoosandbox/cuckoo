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

import sys
from cuckoo.logging.colors import *
from cuckoo.config.costants import *

def logo():
    """
    Prints Cuckoo Sandbox logo
    """
    sys.stdout.write(bold(cyan("                     _                  ")) + "\n")
    sys.stdout.write(bold(cyan("    ____ _   _  ____| |  _ ___   ___    ")) + "\n")
    sys.stdout.write(bold(cyan("   / ___) | | |/ ___) |_/ ) _ \\ / _ \\ ")) + "\n")
    sys.stdout.write(bold(cyan("  ( (___| |_| ( (___|  _ ( |_| | |_| |  ")) + "\n")
    sys.stdout.write(bold(cyan("   \\____)____/ \\____)_| \_)___/ \\___/")) + " " + VERSION + "\n")
    sys.stdout.write("\n")
    sys.stdout.write(" www.cuckoobox.org\n")
    sys.stdout.write(" Copyright (C) 2010-2011\n")
    sys.stdout.write(" by " + bold("Claudio") + " \"nex\" " + bold("Guarnieri") + "\n")
    sys.stdout.write("\n")
