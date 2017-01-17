# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

def test_analyzer():
    """Simply imports the analyzer module to at least load most of the code."""
    import analyzer

    analyzer  # Fake usage.
