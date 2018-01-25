# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

def enumerate_signatures(dirpath, submodule, g, attributes):
    """In the new Cuckoo package, Signatures are no longer accessed
    under the modules module."""
    try:
        from cuckoo.core.plugins import enumerate_plugins
        from cuckoo.common.abstracts import Signature

        return enumerate_plugins(
            dirpath, "signatures.%s" % submodule,
            g, Signature, attributes
        )
    except ImportError:
        from lib.cuckoo.core.plugins import enumerate_plugins
        from lib.cuckoo.common.abstracts import Signature

        return enumerate_plugins(
            dirpath, "modules.signatures.%s" % submodule,
            g, Signature, attributes
        )
