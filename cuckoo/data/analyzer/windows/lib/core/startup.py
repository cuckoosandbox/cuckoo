# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging

from lib.common.defines import KERNEL32, SYSTEMTIME
from lib.common.results import NetlogHandler

log = logging.getLogger()

def init_logging():
    """Initialize logger."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)

    nh = NetlogHandler()
    nh.setFormatter(formatter)
    log.addHandler(nh)

    log.setLevel(logging.DEBUG)

def set_clock(clock):
    st = SYSTEMTIME()
    st.wYear = clock.year
    st.wMonth = clock.month
    st.wDay = clock.day
    st.wHour = clock.hour
    st.wMinute = clock.minute
    st.wSecond = clock.second
    st.wMilliseconds = 0
    KERNEL32.SetLocalTime(ctypes.byref(st))
