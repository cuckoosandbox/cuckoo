# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shutil
import sys
import tempfile

import cuckoo

from cuckoo.common.abstracts import Signature
from cuckoo.core.plugins import RunSignatures, enumerate_plugins
from cuckoo.main import cuckoo_create
from cuckoo.misc import load_signatures, set_cwd, cwd

def test_signature_version():
    rs = RunSignatures({})

    class sig_normal(object):
        name = "sig_normal"
        minimum = "2.0.0"
        maximum = None

    rs.version = "2.0.0"
    assert rs.check_signature_version(sig_normal)

    rs.version = "2.2.0"
    assert rs.check_signature_version(sig_normal)

    class sig_run(object):
        name = "sig_run"
        minimum = "2.0.0"
        maximum = None

        def run(self):
            pass

    assert not rs.check_signature_version(sig_run)

    class sig_outdated(object):
        name = "sig_outdated"
        minimum = "2.0.3"
        maximum = None

    rs.version = "2.0.0"
    assert not rs.check_signature_version(sig_outdated)

    class sig_obsolete(object):
        name = "sig_obsolete"
        minimum = "2.0.0"
        maximum = "2.0.9"

    rs.version = "2.1.0"
    assert not rs.check_signature_version(sig_obsolete)

def test_should_enable_signature():
    rs = RunSignatures({})
    rs.version = "2.0.0"

    class sig_not_enabled(object):
        enabled = False

    assert not rs._should_enable_signature(sig_not_enabled)

    class sig_empty_name(object):
        enabled = True
        name = None

    assert not rs._should_enable_signature(sig_empty_name)

    class sig_enable_false(object):
        enabled = True
        name = "enable_false"
        minimum = "2.0.0"
        maximum = None

        def enable(self):
            return False

    assert not rs._should_enable_signature(sig_enable_false())

    class sig_enable_true(object):
        enabled = True
        name = "enable_true"
        minimum = "2.0.0"
        maximum = None
        platform = None

        def enable(self):
            return True

    assert rs._should_enable_signature(sig_enable_true())

    class sig_empty_platform(object):
        enabled = True
        name = "empty_platform"
        minimum = "2.0.0"
        maximum = None
        platform = None

    assert rs._should_enable_signature(sig_empty_platform())

    class sig_other_platform(object):
        enabled = True
        name = "other_platform"
        minimum = "2.0.0"
        maximum = None
        platform = "nope"

    assert not rs._should_enable_signature(sig_other_platform())

def test_enumerate_plugins():
    sys.path.insert(0, "tests/files")
    plugins = enumerate_plugins(
        "tests/files/enumplugins", "enumplugins",
        globals(), Signature, {"foo": "bar"}
    )
    sys.path.pop(0)

    assert len(plugins) == 3
    assert plugins[0].name == "sig1"
    assert plugins[1].name == "sig2"
    assert plugins[2].name == "sig3"
    assert plugins[0].foo == "bar"
    assert plugins[1].foo == "bar"
    assert plugins[2].foo == "bar"
    assert issubclass(sys.modules["enumplugins"].sig1.Sig1, Signature)
    assert issubclass(sys.modules["enumplugins"].sig2.Sig2, Signature)
    assert issubclass(sys.modules["enumplugins"].sig3.Sig3, Signature)

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

    # Ensure that the Signatures are loaded in the RunSignatures object.
    rs, names = RunSignatures({}), []
    for sig in rs.signatures:
        names.append(sig.__class__.__name__)
    assert "Sig1" in names
    assert "Sig2" in names
    assert "Sig3" in names

def test_libvirt_loaded():
    """KVM is a subclass of LibVirtMachine, which is now autoloaded as well."""
    assert "virtualbox" in cuckoo.machinery.plugins
    assert "kvm" in cuckoo.machinery.plugins
