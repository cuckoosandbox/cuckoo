# Copyright (C) 2014 @threatlead
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

class PcClientMutexes(Signature):
    name = "rat_pcclient"
    description = "Creates known PcClient mutex and/or file changes."
    severity = 3
    categories = ["rat"]
    families = ["pcclient"]
    authors = ["threatlead", "nex", "RedSocks"]
    references = ["https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/"]
    minimum = "2.0"

    mutexes_re = [
        "BKLANG.*",
        "VSLANG.*",
        ".*ps00045695",
        ".*dz00041bc7",
    ]

    files_re = [
        ".*\\\\syslog.dat",
        ".*\\\\.*_lang.ini",
        ".*\\\\[0-9]+_lang.dll",
        ".*\\\\[0-9]+_res.tmp",
        ".*00045695.ini",
        ".*ssewtu.dll",
        ".*hjcpsn.*",
        ".*system32.*Rkmptmy.*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for indicator in self.files_re:
            filepath = self.check_file(pattern=indicator, regex=True)
            if filepath:
                self.mark_ioc("file", filepath)

        return self.has_marks()
