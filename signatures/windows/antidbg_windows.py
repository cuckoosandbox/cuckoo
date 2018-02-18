# Copyright (C) 2012,2016 Claudio "nex" Guarnieri (@botherder), Brad Spengler
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

class AntiDBGWindows(Signature):
    name = "antidbg_windows"
    description = "Checks for the presence of known windows from debuggers and forensic tools"
    severity = 3
    categories = ["anti-debug"]
    authors = ["nex", "KillerInstinct", "Brad Spengler"]
    minimum = "2.0"

    filter_categories = "ui",

    # Lowercase all indicators.
    indicators = [indicator.lower() for indicator in [
        "OLLYDBG",
        "WinDbgFrameClass",
        "pediy06",
        "GBDYLLO",
        "PROCEXPL",
        "Autoruns",
        "gdkWindowTopLevel",
        "API_TRACE_MAIN",
        "TCPViewClass",
        "RegmonClass",
        "FilemonClass",
        "Regmonclass",
        "Filemonclass",
        "PROCMON_WINDOW_CLASS",
        "TCPView - Sysinternals: www.sysinternals.com",
        "File Monitor - Sysinternals: www.sysinternals.com",
        "Process Monitor - Sysinternals: www.sysinternals.com",
        "Registry Monitor - Sysinternals: www.sysinternals.com",
        "Wget [100%%] http://tristan.ssdcorp.net/guid",
        "C:\\Program Files\\Wireshark\\dumpcap.exe",
        "C:\\wireshark\\dumpcap.exe",
        "C:\\SandCastle\\tools\\FakeServer.exe",
        "C:\\\\Python27\\\\python.exe",
        "start.bat - C:\Manual\auto.bat",
        "Fortinet Sunbox",
        "PEiD v0.95",
        "Total Commander 7.0 - Ahnlab Inc.",
        "Total Commander 6.53 - GRISOFT, s.r.o.",
        "Total Commander 7.56a - Avira Soft",
        "Total Commander 7.56a - ROKURA SRL",
        "C:\\strawberry\\perl\\bin\\perl.exe",
        "ThunderRT6FormDC",
        "TfrmMain",
        "Afx:400000:b:10011:6:350167",
        "TApplication",
        "SmartSniff",
        "ConsoleWindowClass",
        "18467-41",
    ]]

    def on_call(self, call, process):
        for indicator in self.indicators:
            window_name = call["arguments"].get("window_name", "").lower()
            class_name = call["arguments"].get("class_name", "").lower()

            if indicator == window_name or indicator == class_name:
                self.mark_call()
                return True
