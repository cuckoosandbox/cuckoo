# Copyright (C) 2012 JoseMi Holguin (@j0sm1)
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

class Ruskill(Signature):
    name = "bot_russkill"
    description = "Creates known Ruskill mutexes"
    severity = 3
    alert = True
    categories = ["bot", "ddos"]
    authors = ["JoseMi Holguin", "nex"]
    minimum = "2.0"

    def on_complete(self):
        mutex = self.check_mutex(pattern="FvLQ49IlzIyLjj6m")
        if mutex:
            self.mark_ioc("mutex", mutex)
            return True
