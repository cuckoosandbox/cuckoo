# Copyright (C) 2015-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from cuckoo.misc import cwd

domains = set()
ips = set()
mispdomains = set()
mispips = set()
mispurls = set()
misphashes = set()

def _load_whitelist(wlset, wl_file):
    wl_path = cwd("whitelist", wl_file)

    if not os.path.isfile(wl_path):
        wl_path = cwd("..", "data", "whitelist", wl_file, private=True)

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

def is_whitelisted_mispdomain(domain):
    if not mispdomains:
        # Initialize the misp domain whitelist.
        _load_whitelist(mispdomains, "mispdomain.txt")

    return domain in mispdomains

def is_whitelisted_mispip(ip):
    if not mispips:
        # Initialize the misp ip whitelist.
        _load_whitelist(mispips, "mispip.txt")

    return ip in mispips

def is_whitelisted_mispurl(url):
    if not mispurls:
        # Initialize the misp url whitelist.
        _load_whitelist(mispurls, "mispurl.txt")

    return url in mispurls

def is_whitelisted_misphash(hash):
    if not misphashes:
        # Initialize the misp hash whitelist.
        _load_whitelist(misphashes, "misphash.txt")

    return hash in misphashes
