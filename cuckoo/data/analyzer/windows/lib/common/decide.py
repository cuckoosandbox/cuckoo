# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.api.process import Process
from lib.core.ioctl import zer0m0n

def dump_memory(pid):
    """Dump process memory using zer0m0n if available, otherwise fallback."""
    if zer0m0n.dumpmem(pid) is False:
        Process(pid=pid).dump_memory()
