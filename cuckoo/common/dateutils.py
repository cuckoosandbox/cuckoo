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

from datetime import datetime

def datetime_to_iso(timestamp):
    """
    Parse a datatime string and returns a datetime in iso format.
    @param timestamp: timestamp string
    @return: ISO datetime
    """  
    if hasattr(datetime, 'strptime'):
        # Python 2.6
        strptime = datetime.strptime
    else:
        # Python 2.4 equivalent
        import time
        strptime = lambda date_string, format: datetime(*(time.strptime(date_string, format)[0:6]))

    return strptime(timestamp, '%Y-%m-%d %H:%M:%S').isoformat()
