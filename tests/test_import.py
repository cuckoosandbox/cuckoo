# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile

from cuckoo.apps.import_ import identify

constants_04_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.4"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_041_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.4.1"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_042_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.4.2"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_05_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.5"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_06_py = """
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.6"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_10_py = """
# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os


_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.0"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_11_py = """
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os


_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.1"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_12_py = """
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.2"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_20rc1_py = """
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "2.0-rc1"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_20rc2_py = """
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "2.0-rc2"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

def drop_constants_py(content):
    dirpath = tempfile.mkdtemp()
    dirpath2 = os.path.join(dirpath, "lib", "cuckoo", "common")
    os.makedirs(dirpath2)
    filepath = os.path.join(dirpath2, "constants.py")
    open(filepath, "wb").write(content)
    return dirpath

def test_identify():
    dirpath = drop_constants_py(constants_04_py)
    assert identify(dirpath) == "0.4"

    dirpath = drop_constants_py(constants_041_py)
    assert identify(dirpath) == "0.4.1"

    dirpath = drop_constants_py(constants_042_py)
    assert identify(dirpath) == "0.4.2"

    dirpath = drop_constants_py(constants_05_py)
    assert identify(dirpath) == "0.5"

    dirpath = drop_constants_py(constants_06_py)
    assert identify(dirpath) == "0.6"

    dirpath = drop_constants_py(constants_10_py)
    assert identify(dirpath) == "1.0"

    dirpath = drop_constants_py(constants_11_py)
    assert identify(dirpath) == "1.1"

    dirpath = drop_constants_py(constants_12_py)
    assert identify(dirpath) == "1.2"

    dirpath = drop_constants_py(constants_20rc1_py)
    assert identify(dirpath) == "2.0-rc1"

    dirpath = drop_constants_py(constants_20rc2_py)
    assert identify(dirpath) == "2.0-rc2"

    dirpath = drop_constants_py("hello world")
    assert identify(dirpath) is None
