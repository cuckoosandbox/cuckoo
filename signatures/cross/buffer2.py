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

class DumpedBuffer2(Signature):
    name = "dumped_buffer2"
    description = "One or more of the buffers contains an embedded PE file"
    severity = 3
    minimum = "2.0"

    def on_complete(self):
        for entry in self.get_results("buffer", []):
            if entry["type"].startswith(("PE32", "MS-DOS")):
                self.mark_ioc("buffer", "Buffer with sha1: %s" % entry["sha1"])

        return self.has_marks()
