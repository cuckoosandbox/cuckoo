# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import logging
import os
import sys

from cuckoo.misc import cwd

log = logging.getLogger(__name__)

# Provide libmagic support in terms of binaries under Windows.
if sys.platform == "win32":
    if sys.maxsize != 0x7fffffff:
        log.warning("libmagic is not supported on 64-bit Python on Windows")
        supported = False
    else:
        supported = True

        os.environ["PATH"] = "%s;%s" % (
            cwd("win32", private=True), os.environ["PATH"]
        )
else:
    supported = True

# Therefore only import libmagic at this point.
if supported:
    import magic

def patch():
    """Patch libmagic to use our magic.mgc file, so that it the same across
    multiple operating systems, Linux distributions, etc."""
    if sys.platform != "win32" or magic._instances:
        return

    magic._instances[False] = magic.Magic(
        mime=False, magic_file=cwd("win32", "magic.mgc", private=True)
    )

    magic._instances[True] = magic.Magic(
        mime=True, magic_file=cwd("win32", "magic.mgc", private=True)
    )

def from_file(*args, **kwargs):
    if not supported:
        return ""

    patch()
    return magic.from_file(*args, **kwargs)

def from_buffer(*args, **kwargs):
    if not supported:
        return ""

    patch()
    return magic.from_buffer(*args, **kwargs)
