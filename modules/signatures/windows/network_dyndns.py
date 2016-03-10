# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class NetworkDynDNS(Signature):
    name = "networkdyndns_checkip"
    description = "Connects to a Dynamic DNS Domain"
    severity = 2
    categories = ["dyndns"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains_re = [
        ".*\\.no-ip\\.",
        ".*\\.strangled\\.net",
        ".*\\.noip\\.",
        ".*\\.x64\\.me",
        ".*\\.ddns\\.",
        ".*\\.myvnc\\.com",
        ".*\\.user32\\.com",
        ".*\\.dyndns\\.",
        ".*\\.codns\\.com",
        ".*\\.servebeer\\.",
        ".*\\.serveminecraft\\.",
        ".*\\.servebbs\\.",
        ".*\\.serveblog\\.",
        ".*\\.servecounterstrike\\.",
        ".*\\.ntdll\\.net",
        ".*\\.servehttp\\.",
        ".*\\.bounceme\\.net",
        ".*\\.servequake\\.com",
        ".*\\.3utilities\\.",
        ".*\\.redirectme\\.net",
        ".*\\.servehalflife\\.com",
        ".*\\.gicp\\.net",
        ".*\\.zapto\\.org",
        ".*\\.hopto\\.org",
        ".*\\.tftpd\\.net",
        ".*\\.myq-see\\.com",
        ".*\\.3322\\.org",
        ".*\\.8866\\.org",
        ".*\\.sytes\\.net",
        ".*\\.serveftp\\.",
        ".*\\.servemp3\\.",
        ".*\\.mooo\\.com",
        ".*\\.dnsget\\.org",
        ".*\\.f3322\\.org",
        ".*\\.publicvm\\.com",
        ".*\\.dlinkddns\\.com",
        ".*\\.authorizeddns\\.",
        ".*\\.chickenkiller\\.",
        ".*\\.8800\\.org",
        ".*\\.adultdns\\.",
        ".*\\.myfreeip\\.",
        ".*\\.linkpc\\.net",
        ".*\\.myftp\\.",
        ".*\\.servegame\\.",
        ".*\\.ignorelist\\.",
        ".*\\.duckdns\\.org",
        ".*\\.ddnsking\\.",
        ".*\\.hopper\\.pw",
        ".*\\.couchpotatofries\\.",
        ".*\\.dyndns.*ip\\.com",
    ]

    def on_complete(self):
        for indicator in self.domains_re:
            match = self.check_domain(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("domain", match)

        return self.has_marks()
