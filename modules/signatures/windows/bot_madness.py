# Copyright (C) 2014 thedude13
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

class Madness(Signature):
    name = "bot_madness"
    description = "Recognized to be an Madness bot"
    severity = 3
    categories = ["bot", "ddos"]
    families = ["madness"]
    authors = ["thedude13", "nex"]
    minimum = "2.0"

    indicator = "\?uid\x3d[0-9]{8}&ver\x3d[0-9].[0-9]{2}&mk\x3d[0-9a-f]{6}&os\x3d[A-Za-z0-9]+&rs\x3d[a-z]+&c\x3d[0-1]&rq\x3d[0-1]"

    def on_complete(self):
        for url in self.check_url(pattern=self.indicator, regex=True, all=True):
            self.mark_ioc("url", url)

        return self.has_marks()
