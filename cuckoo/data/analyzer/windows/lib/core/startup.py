# Copyright (C) 2011-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging

from lib.common.defines import KERNEL32, SYSTEMTIME
from lib.common.results import NetlogHandler, NetlogConnection

log = logging.getLogger()
netlog_handler = None

def init_logging():
    """Initialize logger."""
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)

    global netlog_handler
    netlog_handler = NetlogHandler()
    netlog_handler.setFormatter(formatter)
    log.addHandler(netlog_handler)

    log.setLevel(logging.DEBUG)

def disconnect_logger():
    """Cleanly close the logger. Note that LogHandler also implements close."""
    NetlogConnection.close(netlog_handler)

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
