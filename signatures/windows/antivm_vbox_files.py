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

class VBoxDetectFiles(Signature):
    name = "antivm_vbox_files"
    description = "Detects VirtualBox through the presence of a file"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "2.0"

    indicators = [
        ".*VBoxDisp\\.dll",
        ".*VBoxHook\\.dll",
        ".*VBoxMRXNP\\.dll",
        ".*VBoxOGL\\.dll",
        ".*VBoxOGLarrayspu\\.dll",
        ".*VBoxOGLcrutil\\.dll",
        ".*VBoxOGLerrorspu\\.dll",
        ".*VBoxOGLfeedbackspu\\.dll",
        ".*VBoxOGLpackspu\\.dll",
        ".*VBoxOGLpassthroughspu\\.dll"
        ".*VBoxDisp\\.dll",
        ".*VBoxSF\\.sys",
        ".*VBoxControl\\.exe",
        ".*VBoxService\\.exe",
        ".*VBoxTray\\.exe",
        ".*VBoxDrvInst\\.exe",
        ".*VBoxWHQLFake\\.exe",
        ".*VBoxGuest\\.[a-zA-Z]{3}",
        ".*VBoxMouse\\.[a-zA-Z]{3}",
        ".*VBoxVideo\\.[a-zA-Z]{3}",
        ".*\\\\VirtualBox\\ Guest\\ Additions\\\\uninst\.exe",
        ".*\\\\VirtualBox\\ Guest\\ Additions\\\\uninst\.exe\.dll",
        ".*\\\\vboxmrxnp\.dll"
    ]

    def on_complete(self):
        for indicator in self.indicators:
            filepath = self.check_file(pattern=indicator, regex=True)
            if filepath:
                self.mark_ioc("file", filepath)
                continue

            dll = self.check_dll_loaded(pattern=indicator, regex=True)
            if dll:
                self.mark_ioc("dll", dll)
                continue

        return self.has_marks()
