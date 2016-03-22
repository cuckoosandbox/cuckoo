# Copyright (C) 2014 jjones
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

import re

from lib.cuckoo.common.abstracts import Signature

class AthenaHttp(Signature):
    name = "bot_athenahttp"
    description = "Recognized to be an Athena HTTP bot"
    severity = 3
    categories = ["bot", "ddos"]
    families = ["athenahttp"]
    authors = ["jjones", "nex"]
    minimum = "2.0"

    indicators = [
        "UPDATE__",
        "MAIN_.*",
        "BACKUP_.*",
    ]

    http_body_indicator = re.compile(
        "a=(%[A-Fa-f0-9]{2})+&b=[-A-Za-z0-9+/]+(%3[dD])*&c=(%[A-Fa-f0-9]{2})+"
    )

    def on_complete(self):
        for indicator in self.indicators:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        if self.has_marks(len(self.indicators)):
            return True

        for http in self.get_net_http():
            if http["method"] == "POST" and "body" in http and \
                    self.http_body_indicator.search(http["body"]):
                self.mark_ioc("http", http)

        return self.has_marks(3)
