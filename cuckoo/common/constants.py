# Copyright (C) 2011-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
GITHUB_URL = "https://github.com/cuckoosandbox/cuckoo"
ISSUES_PAGE_URL = "https://github.com/cuckoosandbox/cuckoo/issues"
DOCS_URL = "https://cuckoo.sh/docs"

def faq(entry):
    return "%s/faq/index.html#%s" % (DOCS_URL, entry)
