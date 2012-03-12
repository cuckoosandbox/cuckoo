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
import sys
import logging

try:
    import magic
    IS_MAGIC = True
except ImportError, why:
    IS_MAGIC = False

def get_file_type(file_path):
    """
    Get file format identifier based on the type of the given file.
    @param file_path: file path
    @return: file type identifier or magic signature if format is not supported
    """
    log = logging.getLogger("Common.GetFileType")
    
    if not os.path.exists(file_path):
        return None
    
    if not IS_MAGIC:
        return None

    data = open(file_path, "rb").read()

    # Thanks to Jesse from malc0de.com for this suggestion.
    # First try official magic bindings, if something fails try to failover
    # on the unofficial bindings.
    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(data)
    except:
        try:
            file_type = magic.from_buffer(data)
        except Exception, why:
            log.error("Something went wrong while retrieving magic: %s" % why)
            return None
    
    return file_type
