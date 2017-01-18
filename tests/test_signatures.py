# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.core.plugins import RunSignatures

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
