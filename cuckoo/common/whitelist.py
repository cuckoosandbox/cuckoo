# Copyright (C) 2015-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from cuckoo.misc import cwd

domains = set()
ips = set()

def _load_whitelist(wlset, wl_file):
    for b in (True, False):
        private = {"private": True} if b else {}
        wl_path = cwd("whitelist", wl_file, **private)
        if not os.path.isfile(wl_path):
            continue

        with open(wl_path, "rb") as fp:
            whitelist = fp.read()

        for entry in whitelist.split("\n"):
            entry = entry.strip()
            if entry and not entry.startswith("#"):
                wlset.add(entry)

def is_whitelisted_domain(domain):
    if not domains:
        # Initialize the domain whitelist.
        _load_whitelist(domains, "domain.txt")

    return domain in domains

def is_whitelisted_ip(ip):
    if not ips:
        # Initialize the ip whitelist.
        _load_whitelist(ips, "ip.txt")

    return ip in ips
