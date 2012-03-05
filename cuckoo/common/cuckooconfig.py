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

import os
import sys
import ConfigParser

from cuckoo.common.constants import CUCKOO_CONFIG_FILE

class CuckooConfig:
    """
    Load configuration file and provide access to the options.
    """
    
    def __init__(self):
        """
        Initialize a configuration instance.
        @raise SystemExit: if configuration file is not found
        """
        self.config = None
        self.config_file = CUCKOO_CONFIG_FILE

        if os.path.exists(self.config_file):
            self.config = ConfigParser.ConfigParser()
            self.config.read(self.config_file)
        else:
            sys.stderr.write("Cannot find config file \"%s\". Abort.\n" % self.config_file)
            raise SystemExit

    def logging_debug(self):
        """
        Return boolean for debug logging.
        """
        return self.config.getboolean("Logging", "debug")

    def sniffer_use(self):
        """
        Returns boolean for optional external sniffer.
        """
        return self.config.getboolean("Sniffer", "sniffer")

    def sniffer_path(self):
        """
        Return path to the sniffer tool.
        """
        return self.config.get("Sniffer", "path")

    def sniffer_interface(self):
        """
        Return the network interface to monitor.
        """
        return self.config.get("Sniffer", "interface")

    def analysis_watchdog(self):
        """
        Return the watchdog timeout.
        """
        return self.config.getint("Analysis", "watchdog_timeout")

    def analysis_timeout(self):
        """
        Return the analysis timeout.
        """
        return self.config.getint("Analysis", "analysis_timeout")

    def analysis_results_path(self):
        """
        Return the analysis results path.
        """
        return self.config.get("Analysis", "results_path")

    def analysis_delete_file(self):
        """
        Return boolean for deletion of original file.
        """
        return self.config.getboolean("Analysis", "delete_file")

    def processing_interpreter(self):
        """
        Return path to the intepreter of the processing script.
        """
        return self.config.get("Processing", "interpreter")

    def processing_script(self):
        """
        Return processing script path.
        """
        return self.config.get("Processing", "script")
            
    def virt_engine(self):
        """
        Return virtualization engine.
        """
        return self.config.get("VirtualMachines", "engine")
        
    def virt_mode(self):
        """
        Return virtualization mode.
        """
        return self.config.get("VirtualMachines", "mode")

    def virt_python(self):
        """
        Return virtual machines' local Python path.
        """
        return self.config.get("VirtualMachines", "python")

    def virt_machines(self):
        """
        Return a list of all enabled virtual machines.
        """
        return map(str.strip, self.config.get("VirtualMachines", "enabled").split(","))

    def vm_name(self, vm_id):
        """
        Return the name for the given virtual machine ID.
        @param vm_id: Cuckoo ID of a virtual machine
        """
        return self.config.get(vm_id, "name")

    def vm_username(self, vm_id):
        """
        Return the username for the given virtual machine ID.
        @param vm_id: Cuckoo ID of a virtual machine
        """
        return self.config.get(vm_id, "username")

    def vm_password(self, vm_id):
        """
        Return the password for the given virtual machine ID.
        @param vm_id: Cuckoo ID of a virtual machine
        """
        return self.config.get(vm_id, "password")

    def vm_share(self, vm_id):
        """
        Return the shared folder for the given virtual machine ID.
        @param vm_id: Cuckoo ID of a virtual machine
        """
        return self.config.get(vm_id, "share")
