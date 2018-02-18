# Copyright (C) 2015 Kevin Ross
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

class ModifiesCertificates(Signature):
    name = "modifies_certificates"
    description = "Attempts to create or modify system certificates"
    severity = 3
    categories = ["infostealer", "banker"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\SystemCertificates\\\\.*\\\\Certificates\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\SystemCertificates\\\\.*\\\\Certificates\\\\.*",
    ]

    filter_analysistypes = set(["file"])

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
