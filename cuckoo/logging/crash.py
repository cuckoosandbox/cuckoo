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

import sys
import traceback

import cuckoo.config.constants as constants

def crash():
    """
    Called when a unhandled exception happens, reports all information needed to
    user to ask for support.
    """
    print
    print("------------------------------------[ERROR]-------------------------------------")
    print("Cuckoo stumbled in an unhandled error!")
    print("Before reporting the problem, please run with latest release from the development")
    print("Git repository at:")
    print("  http://github.com/cuckoobox/cuckoo")
    print("If the exception persists, please send the following traceback to:")
    print("  %s" % constants.ML)
    print("The developers will try to reproduce the bug, fix it and get in touch with you.")
    print
    print("----------------------------------[TRACEBACK]-----------------------------------")
    print("Cuckoo version: %s" % constants.VERSION)
    print("Python version: %s" % sys.version)
    print("OS: %s" % sys.platform)
    print("Command line: %s" % " ".join(sys.argv))
    traceback.print_exc()
    print("--------------------------------------------------------------------------------")
    print

