# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import struct

from lib.cuckoo.common.abstracts import Signature

class MetasploitShellcode(Signature):
    name = "metasploit_shellcode"
    description = "A metasploit payload has been detected (shellcode)"
    severity = 5
    categories = ["shellcode"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def init(self):
        self.family = None
        self.type_ = None
        self.url = None

    def on_extract(self, match):
        if match.category != "shellcode":
            return

        for rule in match.yara:
            if not hasattr(self, "extr_%s" % rule.name):
                continue

            self.sc = open(match.raw, "rb").read()
            getattr(self, "extr_%s" % rule.name)(match, rule)

    def extr_meterpreter_reverse_tcp_shellcode(self, match, rule):
        self.type_ = "meterpreter/reverse_tcp"

    def extr_meterpreter_reverse_tcp_shellcode_rev1(self, match, rule):
        self.type_ = "meterpreter/reverse_tcp"
        lhost = rule.meta["LHOST"]
        lport = rule.meta["LPORT"]
        ip = socket.inet_ntoa(self.sc[lhost:lhost+4])
        port = struct.unpack(">H", self.sc[lport:lport+2])[0]
        self.url = "tcp://%s:%s" % (ip, port)

    extr_meterpreter_reverse_tcp_shellcode_rev2 = (
        extr_meterpreter_reverse_tcp_shellcode_rev1
    )

    def extr_metasploit_download_exec_shellcode_rev1(self, match, rule):
        self.type_ = "meterpreter/download_exec"
        url = rule.meta["URL"]
        self.url = self.sc[url:self.sc.find("\x00", url)]

    extr_metasploit_download_exec_shellcode_rev2 = (
        extr_metasploit_download_exec_shellcode_rev1
    )

    def extr_meterpreter_reverse_tcp_shellcode_domain(self, match, rule):
        self.type_ = "meterpreter/reverse_tcp"
        self.url = "tcp://%s" % rule.string("domain")

    def extr_metasploit_bind_shell(self, match, rule):
        self.type_ = "meterpreter/bind_shell"

    def on_complete(self):
        if not self.type_:
            return

        self.mark_config({
            "family": "Metasploit Payload",
            "type": self.type_,
            "url": self.url,
        })
        return True
