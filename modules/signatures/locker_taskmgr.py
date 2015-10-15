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

class DisableTaskMgr(Signature):
    name = "locker_taskmgr"
    description = "Disables Windows' Task Manager"
    severity = 3
    categories = ["locker"]
    authors = ["Thomas Birn", "nex"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.saw_disable = False

    def on_call(self, call, process):
        if self.check_argument_call(call, pattern="DisableTaskMgr",
                                    category="registry"):
            self.saw_disable = True
            self.add_match(process, 'api', call)

    def on_complete(self):
        if self.check_key(pattern=".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System$",
                          regex=True):
            if self.saw_disable:
                return True
