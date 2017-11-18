# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from cuckoo.misc import cwd

domains = set()

def is_whitelisted_domain(domain):
    # Initialize the domain whitelist.
    if not domains:
        for line in open(cwd("whitelist", "domain.txt", private=True), "rb"):
            if not line.strip() or line.startswith("#"):
                continue
            domains.add(line.strip())

        # Collect whitelist also from $CWD if available.
        if os.path.exists(cwd("whitelist", "domain.txt")):
            for line in open(cwd("whitelist", "domain.txt"), "rb"):
                if not line.strip() or line.startswith("#"):
                    continue
                domains.add(line.strip())

    return domain in domains
