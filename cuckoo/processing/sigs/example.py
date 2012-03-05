# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

from cuckoo.processing.signatures import BaseSignature

# This is a working example of a possible signature.
# You should follow the skeleton presented here when writing your own
# signatures.

class Signature(BaseSignature):
    def __init__(self):
        # When creating the signature you should define some basic
        # attributes that will both describe and influence the execution
        # of your signature.
        # First one is a generic identifier.
        self.name = "example"
        # Here describe a detailed description of what this signature should
        # match.
        self.description = "Creates a Windows executable on the filesystem"
        # The severity should be a numeric value that express the level of
        # risk or maliciousness that the action matched represents.
        self.severity = 2
        # Enable or disable this value if you want it to be notified by the
        # alert reporting module.
        self.alert = True
        # Set to True or False if you want to enable or disable this signature
        # from being executed.
        self.enabled = True

    def process(self, results = None):
        # In this function you place the operations, conditions and checks
        # that you want your signature to perform.
        # It's completely up to you what to do inside here, you should just
        # consider that:
        #   - if this function returns True, the signature will be considered
        #     as matched and therefore reported.
        #   - if this function returns False, the signature will NOT be
        #     reported.
        
        if not results:
            return False

        # This signature checks across all the monitored processes, if any
        # of those created a file that looks like a Windows executable.
        for process in results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "CreateFileW":
                    create = False
                    executable = False
                    
                    for argument in call["arguments"]:
                        if (argument["name"] == "lpFileName"
                            and ".exe" in argument["value"]):
                            executable = True
                        elif (argument["name"] == "dwDesiredAccess"
                              and argument["value"] != "GENERIC_READ"
                              and argument["value"] != "ATTRIBUTES"):
                            create = True
                    
                    if create and executable:
                        return True
        
        return False
