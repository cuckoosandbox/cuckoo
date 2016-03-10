# Copyright (C) 2014 Claudio "nex" Guarnieri (@botherder)
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

class Tor2Web(Signature):
    name = "network_tor2web"
    description = "Connects to Tor Hidden Services through Tor2Web"
    severity = 3
    categories = ["network"]
    authors = ["nex"]
    minimum = "2.0"

    indicator = "^.*\.tor2web\.([a-z]{2,3})$"

    def on_complete(self):
        for domain in self.check_domain(pattern=self.indicator, regex=True, all=True):
            self.mark_ioc("domain", domain)

        return self.has_marks()
