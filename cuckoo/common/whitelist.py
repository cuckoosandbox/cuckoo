# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from lib.cuckoo.common.constants import CUCKOO_ROOT

domains = set()

def is_whitelisted_domain(domain):
    return domain in domains

# Initialize the domain whitelist.
for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "domain.txt")):
    domains.add(domain.strip())
