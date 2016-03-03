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

class AntiSandboxForegroundWindow(Signature):
    name = "antisandbox_foregroundwindows"
    description = "Checks whether any human activity is being performed " \
        "by constantly checking whether the foreground window changed"
    severity = 2
    categories = ["anti-sandbox"]
    minimum = "2.0"

    references = [
        "https://www.virusbtn.com/virusbulletin/archive/2015/09/vb201509-custom-packer.dkb",
    ]

    def on_complete(self):
        apistats = self.get_results("behavior", {}).get("apistats", {})
        for funcs in apistats.values():
            # The check for NtDelayExecution may not be necessary, but then
            # this signature has more potential of triggering a false positive.
            if funcs.get("GetForegroundWindow", 0) > 100 and \
                    funcs.get("NtDelayExecution", 0) > 100:
                return True
