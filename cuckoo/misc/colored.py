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

import logging

from cuckoo.misc.colors import *

def color_stream_emit(fn):
    def new(*args):
        root = logging.getLogger()
        default_level = root.level
        levelno = args[1].levelno
        if(levelno >= 50):
            args[1].msg = bold(red(args[1].msg))
        elif(levelno >= 40):
            args[1].msg = red(args[1].msg)
        elif(levelno >= 30):
            args[1].msg = yellow(args[1].msg)
        elif(levelno >= 20):
            if default_level == 10:
                args[1].msg = cyan(args[1].msg)

        return fn(*args)

    return new
