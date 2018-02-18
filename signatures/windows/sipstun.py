# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SipStun(Signature):
    name = "SipStun"
    description = "Connects to SIP Stun Server"
    severity = 2
    categories = [""]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains = [
        "s1.tarabara.net",
        "s1.voipstation.jp",
        "s2.tarabara.net",
        "s2.voipstation.jp",
        "sip.iptel.org",
        "stun.2talk.co.nz",
        "stun.callwithus.com",
        "stun.ekiga.net",
        "stun.faktortel.com.au",
        "stun.ideasip.com",
        "stun.internetcalls.com",
        "stun.ipshka.com",
        "stun.iptel.org",
        "stun.l.google.com",
        "stun.noc.ams-ix.net",
        "stun.phonepower.com",
        "stun.rixtelecom.se",
        "stun.schlund.de",
        "stun.sip.telia.com",
        "stun.sipgate.net",
        "stun01.sipphone.com",
        "stun.sipgate.net",
        "stun.softjoys.com",
        "stun.stunprotocol.org",
        "stun.voip.aebc.com",
        "stun.voiparound.com",
        "stun.voipbuster.com",
        "stun.voipdiscount.com",
        "stun.voipstunt.com",
        "stun.voxgratia.org",
        "stun.xten.com",
        "stun1.ams-ix.net",
        "stun1.l.google.com",
        "stun1.voiceeclipse.net",
        "stun2.l.google.com",
        "stun4.l.google.com",
        "stunserver.org",
        "stun.qq.cn",
    ]

    def on_complete(self):
        for indicator in self.domains:
            if self.check_domain(pattern=indicator):
                self.mark_ioc("domain", indicator)
                return True
