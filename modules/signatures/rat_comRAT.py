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

REG_SUBKEY = "{DFFACDC5-679F-4156-8947-C5C76BC0B67F}\InprocServer32"
MOVE_FILE = ["Microsoft\\\shdocvw.tlb", "Microsoft\\\oleaut32.dll", 
             "Microsoft\\\oleaut32.tlb", "Microsoft\\\credprov.tlb",
             "Microsoft\\\libadcodec.dll", "Microsoft\\\libadcodec.tlb"]

class ComRAT(Signature):
    name = "rat_comRAT"
    description = "Turla-APT-Campaign: ComRAT"
    severity = 3
    alert = True
    categories = ["APT", "RAT"]
    families = ["Turla", "Uroburos", "Snake"]
    authors = ["Robby Zeitfuchs", "@robbyFux"]
    minimum = "1.0"
    references = ["https://blog.gdatasoftware.com/blog/article/the-uroburos-case-new-sophisticated-rat-identified.html",
                  "https://malwr.com/analysis/NjJiODNlNjE4NjAwNDc3MGE4NmM1YzBmMzhlZjNiYTY/",
                  "https://malwr.com/analysis/ZTE5MTMzODk1OGVkNDhiODg1ZDE3ZWM5MThjMmRiNjY/"]   
    
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ioc = {"initProcessName": None,
                    "countMoveFiles" : 0,
                    "matchRegKey" : False,
                    "writeExeFile" : False,
                    "createProcess" : False}
        
    evented = True
    filter_categories = set(["process","registry", "filesystem"])
    filter_apinames = set(["NtOpenFile", "NtCreateFile", "DeleteFileW", "MoveFileWithProgressW", 
                           "RegCreateKeyExW", "NtWriteFile", "CreateProcessInternalW"])
    filter_processnames = set()
    
    def on_call(self, call, process):  
        # Determine initial process name
        if not self.ioc["initProcessName"]:
            self.ioc["initProcessName"] = process["process_name"]
              
        if call["api"].startswith("RegCreateKeyEx"):
            # check RegKey InprocServer32
            if self.get_argument(call,"SubKey").endswith(REG_SUBKEY):
                self.data.append({'process':process["process_name"], 'type': call["category"], 'value': REG_SUBKEY})
                self.ioc["matchRegKey"] = True
        
        elif call["api"].startswith("MoveFileWithProgress"):
            if self.get_argument(call,"NewFileName").endswith(".tmp"):
                # move files
                for file in MOVE_FILE:
                    if self.get_argument(call,"ExistingFileName").endswith(file):
                        self.data.append({'process':process["process_name"], 'type': call["category"], 
                                          'value': self.get_argument(call,"ExistingFileName")})
                        self.ioc["countMoveFiles"] += 1
                        break 
        elif call["api"].startswith("CreateProcessInternal"):
            # start rundll32.exe Install?
            cmd = self.get_argument(call,"CommandLine")
            if "rundll32.exe" in cmd and "Install" in cmd:
                self.data.append({'process':process["process_name"], 'type': call["category"], 'value': cmd})
                self.ioc["createProcess"] = True
  
        elif call["api"].startswith("NtWriteFile"):
            if process["process_name"] == self.ioc["initProcessName"] and self.get_argument(call,"Buffer")[0:2] == "MZ":
                self.ioc["writeExeFile"] = True

        return None
    
    def on_complete(self):
        # check IOC
        if not self.ioc["matchRegKey"] or not self.ioc["writeExeFile"] or not self.ioc["createProcess"]:
            return False
        if len(MOVE_FILE) != self.ioc["countMoveFiles"]:
            return False
        
        return True
