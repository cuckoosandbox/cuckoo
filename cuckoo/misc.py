# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path

import cuckoo

log = logging.getLogger(__name__)

# Cuckoo Working Directory base path.
_root = None

def set_cwd(path):
    global _root
    _root = path

def cwd(*args, **kwargs):
    """Returns absolute path to this file in the Cuckoo Working Directory or
    optionally - when private=True has been passed along - to our private
    Cuckoo Working Directory which is not configurable."""
    if kwargs.pop("private", False):
        return os.path.join(cuckoo.__path__[0], "data-private", *args)
    else:
        return os.path.join(_root, *args)

def mkdir(*args):
    """Create a directory without throwing exceptions if it already exists."""
    dirpath = os.path.join(*args)
    if not os.path.isdir(dirpath):
        os.mkdir(dirpath)
