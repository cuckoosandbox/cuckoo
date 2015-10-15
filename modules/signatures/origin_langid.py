# Copyright (C) 2012 Benjamin K., Kevin R., Claudio "nex" Guarnieri
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

class BuildLangID(Signature):
    name = "origin_langid"
    description = "Unconventional binary language"
    severity = 2
    authors = ["Benjamin K.", "Kevin R.", "nex"]
    categories = ["origin"]
    minimum = "0.5"

    def run(self):
        languages = [
            {"language" : "Arabic", "code" : "0x0401"},
            {"language" : "Bulgarian", "code" : "0x0402"},
            {"language" : "Traditional Chinese" , "code" : "0x0404"},
            {"language" : "Romanian", "code" : "0x0418"},
            {"language" : "Russian", "code" : "0x0419"},
            {"language" : "Croato-Serbian", "code" : "0x041A"},
            {"language" : "Slovak", "code" : "0x041B"},
            {"language" : "Albanian", "code" : "0x041C"},
            {"language" : "Turkish", "code" : "0x041F"},
            {"language" : "Simplified Chinese", "code" : "0x0804"},
            {"language" : "Hebrew", "code" : "0x040d"}
        ]

        if "static" in self.results:
            if "pe_versioninfo" in self.results["static"]:
                for info in self.results["static"]["pe_versioninfo"]:
                    if info["name"] == "Translation":
                        lang, charset = info["value"].strip().split(" ")
                        for language in languages:
                            if language["code"] == lang:
                                self.description += ": %s" % language["language"]
                                return True

        return False
