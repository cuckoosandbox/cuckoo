# Copyright (C) 2012 Michael Boman (@mboman), Optiv, Inc. (brad.spengler@optiv.com), Kevin Ross
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

class KnownVirustotal(Signature):
    name = "antivirus_virustotal"
    description = "File has been identified by at least one AntiVirus engine on VirusTotal as malicious"
    severity = 2
    categories = ["antivirus"]
    authors = ["Michael Boman", "nex", "Optiv", "Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        results = self.get_virustotal()
        if results.get("positives"):
            positives = results.get("positives")
            if positives == 1:
                self.description = "File has been identified by one AntiVirus engine on VirusTotal as malicious"
            elif positives > 1:
                self.description = "File has been identified by %s AntiVirus engines on VirusTotal as malicious" % positives
                if positives >= 40:
                    self.severity = 6
                elif positives >= 30:
                    self.severity = 5
                elif positives >= 20:
                    self.severity = 4
                elif positives >= 10:
                    self.severity = 3

            for engine, signature in results["scans"].items():
                if signature["detected"]:
                    self.mark_ioc(engine, signature["result"])

        return self.has_marks()
