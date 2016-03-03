# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class SpyEyeMutexes(Signature):
    name = "banker_spyeye_mutexes"
    description = "Creates known SpyEye mutexes"
    severity = 3
    categories = ["banker"]
    families = ["spyeye"]
    authors = ["nex", "RedSocks"]
    minimum = "2.0"

    indicators = [
        "zXeRY3a_PtW.*",
        "SPYNET",
        "__CLEANSWEEP__",
        "__CLEANSWEEP_UNINSTALL__",
        "__CLEANSWEEP_RELOADCFG__",
        "syjfyhb",
        "Global.*wiuuyei",
        "Global.*ovxpcyv",
        "Global.*rzouciao",
        "Global.*siijtlt",
        "Global.*hhvaua",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
