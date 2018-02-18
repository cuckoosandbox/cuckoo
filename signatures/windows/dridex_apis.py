# Copyright (C) 2015-2016 KillerInstinct, Updated 2016 for Cuckoo 2.0
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Dridex_APIs(Signature):
    name = "dridex_behavior"
    description = "Exhibits behavior characteristic of Dridex malware"
    weight = 3
    severity = 3
    categories = ["banker", "trojan"]
    families = ["dridex"]
    authors = ["KillerInstinct"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compname = ""
        self.username = ""
        self.is_xp = False
        self.crypted = []
        # Set to false if you don't want to extract c2 IPs
        self.extract = True
        self.sockmon = dict()
        self.payloadip = dict()
        self.decompMZ = False
        self.ip_check = str()
        self.port_check = str()
        self.post_check = False
        self.ret = False
        self.isdridex = False
        self.cncstart = False
        self.whitelist_ports = ["80", "8080", "443", "8443"]

    filter_apinames = set(["RegQueryValueExA", "CryptHashData", "connect", "send", "recv",
                           "RtlDecompressBuffer", "InternetConnectW", "HttpOpenRequestW",
                           "InternetCrackUrlA", "HttpSendRequestW"])

    def on_call(self, call, process):
        if call["api"] == "RegQueryValueExA":
            if "regkey" not in call["arguments"]:
                return

            # There are many more ways to get the computer name, this is the
            # pattern observed with all Dridex varients 08/14 - 03/15 so far.
            testkey = call["arguments"]["regkey"].lower()
            if testkey == "hkey_local_machine\\system\\controlset001\\control\\computername\\computername\\computername":
                buf = call["arguments"]["value"]
                if buf:
                    self.compname = buf.lower()
                    self.mark_call()
            if testkey == "hkey_current_user\\volatile environment\\username":
                if call["status"]:
                    buf = call["arguments"]["value"]
                    if buf:
                        self.username = buf.lower()
                        self.mark_call()
                else:
                    self.is_xp = True

        elif call["api"] == "CryptHashData":
            if "buffer" not in call["arguments"]:
                return

            buf = call["arguments"]["buffer"].lower()
            self.crypted.append(buf)
            if self.username in buf or self.compname in buf:
                self.mark_call()

        elif call["api"] == "connect":
            if not self.extract:
                return None

            if not "socket" in call["arguments"]:
                return None

            socknum = str(call["arguments"]["socket"])
            if socknum and socknum not in self.sockmon.keys():
                self.sockmon[socknum] = ""

            if not "ip" in call["arguments"]:
                return None
            lastip = call["arguments"]["ip"]
            self.sockmon[socknum] = lastip

        elif call["api"] == "send":
            if not self.extract:
                return None

            if not "socket" in call["arguments"]:
                return None

            socknum = str(call["arguments"]["socket"])
            if socknum and socknum in self.sockmon.keys() and "buffer" in call["arguments"]:
                buf = call["arguments"]["buffer"]
                # POST is a stable indicator observed so far
                if buf and buf[:4] == "POST":
                    self.payloadip["send"] = self.sockmon[socknum]
                    self.mark_call()

        elif call["api"] == "recv":
            if not self.extract:
                return None

            if not "socket" in call["arguments"]:
                return None

            socknum = str(call["arguments"]["socket"])
            if socknum and socknum in self.sockmon.keys() and "buffer" in call["arguments"]:
                buf = call["arguments"]["buffer"]
                if buf:
                    clen = re.search(r"Content-Length:\s([^\s]+)", buf)
                    if clen:
                        length = int(clen.group(1))
                        if length > 100000:
                            if "send" in self.payloadip and self.sockmon[socknum] == self.payloadip["send"]:
                                # Just a sanity check to make sure the IP hasn't changed
                                # since this is a primitive send/recv monitor
                                self.payloadip["recv"] = self.sockmon[socknum]
                                self.mark_call()

        elif call["api"] == "RtlDecompressBuffer":
            if not "uncompressed_buffer" in call["arguments"]:
                return None

            buf = call["arguments"]["uncompressed_buffer"]
            if buf.startswith("MZ"):
                self.decompMZ = True
                self.mark_call()

        elif call["api"] == "InternetConnectW":
            if not "hostname" in call["arguments"] or not "port" in call["arguments"]:
                return None

            if self.decompMZ:
                ip = call["arguments"]["hostname"]
                if not any(char.isalpha() for char in ip):
                    self.ip_check = ip
                    self.port_check = str(call["arguments"]["port"])
            elif call["arguments"]["port"] not in self.whitelist_ports:
                self.cncstart = True
                self.mark_call()

        elif call["api"] == "HttpOpenRequestW":
            if not "http_method" in call["arguments"]:
                return None

            if self.ip_check and self.port_check:
                if call["arguments"]["http_method"] == "POST":
                    self.post_check = True
            elif self.cncstart:
                self.mark_call()

        elif call["api"] == "InternetCrackUrlA":
            if not "url" in call["arguments"]:
                return None

            if self.post_check:
                buf = call["arguments"]["url"]
                if buf.lower().startswith("https") and self.port_check != "443":
                    if buf.lower().split("/")[-1] == self.ip_check:
                        self.isdridex = True
                        self.mark_call()
            elif self.cncstart:
                self.mark_call()

        elif call["api"] == "HttpSendRequestW" and self.cncstart:
                self.mark_call()

        return None

    def on_complete(self):
        if self.compname and (self.username or self.is_xp) and self.crypted:
            buf = self.compname + self.username
            for item in self.crypted:
                if buf in item:
                    self.isdridex = True

        # TO BE FIXED UP. OLDER SAMPLES BUT WANT TO BRING INLINE WITH REST OF RESULTS MARKING API CALLS
        #pattern = r".*\\CurrentVersion\\Explorer\\CLSID\\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\ShellFolder\\[0-9A-Fa-f]{8,24}"
        #if self.check_key(pattern=pattern, regex=True, actions=["regkey_written"], all=True):
        #    self.isdridex = True

        if self.isdridex:
            return self.has_marks()
