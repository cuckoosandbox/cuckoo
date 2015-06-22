# Copyright (C) 2015 Robby Zeitfuchs (@robbyFux)
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

REG_SUBKEY = "ActiveComputerName"
CONFIG_BUFFER_STRINGS = ["[NAME]", "[TIME]", "iproc", "user_winmin", "user_winmax", "object_id"]
EXPLORER_EXE = "explorer.exe"

class TurlaCarbon(Signature):
    name = "apt_turlacarbon"
    description = "Appears to be the targeted Turla Carbon malware"
    severity = 3
    alert = True
    categories = ["apt"]
    families = ["turla", "uroburos", "snake"]
    authors = ["Robby Zeitfuchs", "@robbyFux"]
    minimum = "1.0"
    references = ["https://blog.gdatasoftware.com/blog/article/analysis-of-project-cobra.html",
                  "https://malwr.com/analysis/MTI2M2RjYTAyZmNmNDE4ZTk5MDBkZjA4MDA5ZTFjMDc/"]   
    
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ioc = {"explorerExeFileHandle": None,
                    "confFileName": None,
                    "openConfig": False,
                    "matchRegKey" : False,
                    "matchConfig" : False}
        
    evented = True
    filter_categories = set(["registry", "filesystem"])
    filter_apinames = set(["NtCreateFile", "NtWriteFile", "NtOpenFile", "NtOpenKey"])
    filter_processnames = set()
    
    def on_call(self, call, process):  
        if call["api"].startswith("NtOpenKey"):
            # check RegKey ActiveComputerName
            if self.get_argument(call,"ObjectAttributes").endswith(REG_SUBKEY):
                self.data.append({'process':process["process_name"], 'type': call["category"], 'value': REG_SUBKEY})
                self.ioc["matchRegKey"] = True

        elif call["api"].startswith("NtCreateFile"):
            # get file handle
            if self.get_argument(call,"FileName").endswith(EXPLORER_EXE):
                self.ioc["explorerExeFileHandle"] = self.get_argument(call,"FileHandle")
            elif self.get_argument(call,"FileHandle") == self.ioc["explorerExeFileHandle"] and not \
                self.ioc["confFileName"]:
                self.ioc["confFileName"] = self.get_argument(call,"FileName")

        elif call["api"].startswith("NtOpenFile") and self.ioc["explorerExeFileHandle"]:
            # check open config file
            if self.get_argument(call,"FileHandle") == self.ioc["explorerExeFileHandle"] and \
                self.ioc["confFileName"] == self.get_argument(call,"FileName"):
                self.ioc["openConfig"] = True
        
        elif call["api"].startswith("NtWriteFile") and self.ioc["explorerExeFileHandle"]:
            # check config-file buffer
            if self.get_argument(call,"FileHandle") == self.ioc["explorerExeFileHandle"]:
                buffer = self.get_argument(call,"Buffer")
                self.ioc["matchConfig"] = True
                
                for str in CONFIG_BUFFER_STRINGS:
                    if not str in buffer:
                        self.ioc["matchConfig"] = False
                        break
                    
                if self.ioc["matchConfig"]:
                    self.data.append({'process':process["process_name"], 'confFile': self.ioc["confFileName"], 'value': buffer})
        
        return None
    
    def on_complete(self):
        # check IOC
        if not self.ioc["matchRegKey"] or not self.ioc["matchConfig"] or not self.ioc["openConfig"]:
            return False
        
        return True
