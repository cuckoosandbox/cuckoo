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

def _load_safelist(wlset, wl_file):
    wl_path = cwd("safelist", wl_file)

    if not os.path.isfile(wl_path):
        wl_path = cwd("..", "data", "safelist", wl_file, private=True)

    with open(wl_path, "rb") as fp:
        safelist = fp.read()

    for entry in safelist.split("\n"):
        entry = entry.strip()
        if entry and not entry.startswith("#"):
            wlset.add(entry)

def is_safelisted_domain(domain):
    if not domains:
        # Initialize the domain safelist.
        _load_safelist(domains, "domain.txt")

    return domain in domains

def is_safelisted_ip(ip):
    if not ips:
        # Initialize the ip safelist.
        _load_safelist(ips, "ip.txt")

    return ip in ips

def is_safelisted_mispdomain(domain):
    if not mispdomains:
        # Initialize the misp domain safelist.
        _load_safelist(mispdomains, "mispdomain.txt")

    return domain in mispdomains

def is_safelisted_mispip(ip):
    if not mispips:
        # Initialize the misp ip safelist.
        _load_safelist(mispips, "mispip.txt")

    return ip in mispips

def is_safelisted_mispurl(url):
    if not mispurls:
        # Initialize the misp url safelist.
        _load_safelist(mispurls, "mispurl.txt")

    return url in mispurls

def is_safelisted_misphash(hash):
    if not misphashes:
        # Initialize the misp hash safelist.
        _load_safelist(misphashes, "misphash.txt")

    return hash in misphashes
