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
    minimum = "1.2"

    def run(self):
        domain = self.check_domain(pattern="^.*\.tor2web\.([a-z]{2,3})$", regex=True)
        if domain:
            self.add_match(None, "domain", domain)
            return True

        return False
