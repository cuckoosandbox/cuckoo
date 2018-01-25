# Copyright (C) 2015 KillerInstinct, 2016 Kevin Ross. Original Signature (features are currently missing in translation) https://github.com/kevross33/community-modified-1/blob/d999da9a25ce70f5b93bbea08242834f5b4069a4/modules/signatures/recon_beacon.py
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

from lib.cuckoo.common.abstracts import Signature

class Recon_Beacon(Signature):
    name = "recon_beacon"
    description = "A process performed obfuscation on information about the computer or sent it to a remote location indicative of CnC Traffic/Preperations."
    weight = 2
    severity = 3
    categories = ["network", "recon"]
    authors = ["KillerInstinct", "Kevin Ross"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.computerdetails = []

    filter_apinames = set(["GetComputerNameA","GetComputerNameW","GetUserNameA",
                            "GetUserNameW","HttpSendRequestA","HttpSendRequestW",
                            "HttpOpenRequestA","HttpOpenRequestW","InternetCrackUrlA",
                            "InternetCrackUrlW","WSASend","CryptHashData"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        # Here we check for interesting bits of data which may be queried and used in cnc for computer identification
        if call["api"] == "GetComputerNameA" or call["api"] == "GetComputerNameW":
            if "computer_name" not in call["arguments"]:
                return

            compname = call["arguments"]["computer_name"]
            if compname:
                self.computerdetails.append(compname)

        elif call["api"] == "GetUserNameA" or call["api"] == "GetUserNameW":
            if "user_name" not in call["arguments"]:
                return

            compname = call["arguments"]["user_name"]
            if compname:
                self.computerdetails.append(compname)

        # Here we check for the interesting data appearing in buffers from network calls for CnC
        elif call["api"] == "HttpSendRequestA" or call["api"] == "HttpSendRequestW":
            if "post_data" not in call["arguments"]:
                return

            buff = call["arguments"]["post_data"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif call["api"] == "HttpOpenRequestA" or call["api"] == "HttpOpenRequestW":
            if "path" not in call["arguments"]:
                return

            buff = call["arguments"]["path"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif call["api"] == "InternetCrackUrlW" or call["api"] == "InternetCrackUrlW":
            if "url" not in call["arguments"]:
                return

            buff = call["arguments"]["url"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif call["api"] == "WSASend" and "buffer" in call["arguments"]:
            buff = call["arguments"]["buffer"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        # Here we check API calls which may be used for obfuscating data prior to CnC
        elif call["api"] == "CryptHashData" and "buffer" in call["arguments"]:
            buff = call["arguments"]["buffer"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

    def on_complete(self):
        return self.has_marks()

