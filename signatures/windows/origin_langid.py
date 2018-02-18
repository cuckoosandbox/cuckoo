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
    description = "Foreign language identified in PE resource"
    severity = 2
    authors = ["Benjamin K.", "Kevin Ross", "nex", "RedSocks"]
    categories = ["origin"]
    minimum = "2.0"

    languages = [
        "ALBANIAN",
        "ARABIC",
        "BOSNIAN",
        "CHINESE",
        "ESTONIAN",
        "JAPANESE",
        "GAILIC",
        "GEORGIAN",
        "KASHMIRI",
        "KAZAKH",
        "KHMER",
        "KOREAN",
        "KYRGYZ",
        "LATVIAN",
        "LITHUANIAN",
        "MOLDOVIAN",
        "MONGOLIAN",
        "PORTUGUESE",
        "SERBIAN",
        "SUBLANG_ENGLISH_AUS",
        "ROMANIAN"
        "RUSSIAN",
        "TIBETAN",
        "TURKISH",
        "UKRAINIAN",
        "YIDDISH",
        "ZULU"
    ]

    def on_complete(self):
        for resource in self.get_results("static", {}).get("pe_resources", []):
            for language in self.languages:
                r = 0
                if resource["language"] and language in resource["language"]:
                    r += 1

                if resource["sublanguage"] and language in resource["sublanguage"]:
                    r += 2

                if r:
                    self.mark(
                        name=resource["name"],
                        language=resource["language"],
                        filetype=resource["filetype"],
                        sublanguage=resource["sublanguage"],
                        offset=resource["offset"],
                        size=resource["size"],
                    )

        return self.has_marks()
