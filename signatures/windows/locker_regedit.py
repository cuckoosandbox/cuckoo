# Copyright (C) 2012 Thomas "stacks" Birn (@stacksth)
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

class DisableRegedit(Signature):
    name = "locker_regedit"
    description = "Disables Windows' Registry Editor"
    severity = 2
    categories = ["locker"]
    authors = ["Thomas Birn", "nex"]
    minimum = "2.0"

    indicator = ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion" \
        "\\\\Policies\\\\System\\DisableRegistryTools$"

    def on_complete(self):
        for regkey in self.check_key(pattern=self.indicator, regex=True, actions=["regkey_written"], all=True):
            self.mark_ioc("registry", regkey)

        return self.has_marks()
