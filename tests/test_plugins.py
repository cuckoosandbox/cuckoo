# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
import shutil
import sys
import tempfile

import cuckoo

from cuckoo.common.abstracts import Signature
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Files
from cuckoo.core.plugins import RunSignatures, enumerate_plugins
from cuckoo.main import cuckoo_create
from cuckoo.misc import load_signatures, set_cwd, cwd

def test_enumerate_plugins():
    sys.path.insert(0, "tests/files")
    plugins = enumerate_plugins(
        "tests/files/enumplugins", "enumplugins",
        globals(), Signature, {"foo": "bar"}
    )
    sys.path.pop(0)

    assert len(plugins) == 5
    assert [plugin.name for plugin in plugins] == ["sig1", "sig2", "sig3", "sigsub1", "sigsub2"]
    assert all([plugin.foo == "bar" for plugin in plugins])
    assert issubclass(sys.modules["enumplugins"].sig1.Sig1, Signature)
    assert issubclass(sys.modules["enumplugins"].sig2.Sig2, Signature)
    assert issubclass(sys.modules["enumplugins"].sig3.Sig3, Signature)
    assert issubclass(sys.modules["enumplugins"].sigsub.Sigsub1, Signature)
    assert issubclass(sys.modules["enumplugins"].sigsub.Sigsub2, Signature)

def test_load_signatures():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    shutil.rmtree(cwd("signatures"))
    shutil.copytree("tests/files/enumplugins", cwd("signatures"))
    sys.modules.pop("signatures", None)
    load_signatures()

    # Ensure that the Signatures are loaded in the global list.
    names = []
    for sig in cuckoo.signatures:
        names.append(sig.__module__)
    assert "signatures.sig1" in names
    assert "signatures.sig2" in names
    assert "signatures.sig3" in names
    assert "signatures.sigsub.sigsub1" in names
    assert "signatures.sigsub.sigsub2" in names

    # Ensure that the Signatures are loaded in the RunSignatures object.
    RunSignatures.init_once()
    rs, names = RunSignatures({}), []
    for sig in rs.signatures:
        names.append(sig.__class__.__name__)
    assert "Sig1" in names
    assert "Sig2" in names
    assert "Sig3" in names
    assert "Sigsub1" in names
    assert "Sigsub2" in names

def test_libvirt_loaded():
    """KVM is a subclass of LibVirtMachine, which is now autoloaded as well."""
    assert "virtualbox" in cuckoo.machinery.plugins
    assert "kvm" in cuckoo.machinery.plugins

def test_invalid_plugin():
    dirpath = tempfile.mkdtemp()
    Files.create(dirpath, "foo.py", "import foobarnotexist")

    with pytest.raises(CuckooOperationalError) as e:
        enumerate_plugins(dirpath, "enumplugins", globals(), Signature, {})
    e.match("Unable to load the Cuckoo plugin")
