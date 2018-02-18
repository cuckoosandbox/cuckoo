# Copyright (C) 2016 Kevin Ross
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

class NetworkC2Details(Signature):
    name = "network_c2_details"
    description = "Queried details from the computer were then used in a network or crypto API call indicative of command and control communications/preperations"
    severity = 3
    categories = ["infostealer","c2","network"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.computerdetails = []

    filter_apinames = set(["GetComputerNameA","GetUserNameA","GetComputerNameW","GetUserNameW","CryptHashData","HttpSendRequestW","HttpOpenRequestW","InternetCrackUrlW","WSASend"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        # Here we check for interesting bits of data which may be queried and used in cnc for computer identification
        api = call["api"]
        if (api == "GetComputerNameA" or api == "GetComputerNameW" and
                "computer_name" in call["arguments"]):
            compname = call["arguments"]["computer_name"]
            if compname:
                self.computerdetails.append(compname)

        if ((api == "GetUserNameA" or api == "GetUserNameW") and
                "user_name" in call["arguments"]):
            compname = call["arguments"]["user_name"]
            if compname:
                self.computerdetails.append(compname)

        # Here we check for the interesting data appearing in buffers from network and crypto calls
        elif api == "CryptHashData" and "buffer" in call["arguments"]:
            buff = call["arguments"]["buffer"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif api == "HttpSendRequestW" and "post_data" in call["arguments"]:
            buff = call["arguments"]["post_data"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif api == "HttpOpenRequestW" and "path" in call["arguments"]:
            buff = call["arguments"]["path"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif api == "InternetCrackUrlW" and "url" in call["arguments"]:
            buff = call["arguments"]["url"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

        elif api == "WSASend" and "buffer" in call["arguments"]:
            buff = call["arguments"]["buffer"]
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.mark_call()

    def on_complete(self):
        return self.has_marks()
