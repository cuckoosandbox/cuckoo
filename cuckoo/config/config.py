# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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
import logging
import ConfigParser

from cuckoo.logging.colors import *
from cuckoo.config.constants import CUCKOO_CONFIG_FILE

class CuckooConfig:
    """
    Loads configuration file and exposes getter to configuration
    """
    
    def __init__(self):
        """
        Initialize configuration instance.
        @raise SystemExit: if configuration file is not found
        """
        self.config = None
        self.config_file = CUCKOO_CONFIG_FILE

        if os.path.exists(self.config_file):
            try:
                self.config = ConfigParser.ConfigParser()
                self.config.read(self.config_file)
            except Exception, why:
                print(red("[Config] [ERROR] Cannot read config file \"%s\": %s."
                          % (self.config_file, why)))
                sys.exit(-1)
        else:
            print(red("[Config] [ERROR] Cannot find config file \"%s\"."
                      % self.config_file))
            sys.exit(-1)

    def _error_parse(self, why):
        """
        Prints a parsing error.
        @param why: Error message to be printed 
        """
        print(red("[Config] [ERROR] Error parsing config file: \"%s\": %s."
                  % (self.config_file, why)))

    def _error_config(self):
        """
        Prints an error.
        """
        print(red("[Config] [ERROR] ConfigParser not properly initialized."))

    def get_logging_debug(self):
        """
        Returns logging debug option value.
        """
        if self.config:
            try:
                return self.config.getboolean("Logging", "debug")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def use_external_sniffer(self):
        """
        Returns the option for an external sniffer.
        """
        if self.config:
            try:
                return self.config.getboolean("Sniffer", "sniffer")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_sniffer_path(self):
        """
        Returns path to sniffer binary.
        """
        if self.config:
            try:
                return self.config.get("Sniffer", "path")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_sniffer_interface(self):
        """
        Returns network interface name to sniff.
        """
        if self.config:
            try:
                return self.config.get("Sniffer", "interface")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_analysis_watchdog_timeout(self):
        """
        Returns watchdog timeout.
        """
        if self.config:
            try:
                return self.config.getint("Analysis", "watchdog_timeout")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_analysis_analysis_timeout(self):
        """
        Returns maximum analysis timeout.
        """
        if self.config:
            try:
                return self.config.getint("Analysis", "analysis_timeout")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_analysis_results_path(self):
        """
        Returns path where to store analysis path.
        """
        if self.config:
            try:
                return self.config.get("Analysis", "results_path")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None
    
    def get_analysis_delete_original(self):
        """
        Returns a boolean instructing whether the original file should be
        deleted or not.
        """
        if self.config:
            try:
                return self.config.getboolean("Analysis", "delete_original")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_processing_interpreter(self):
        """
        Returns processing interpreter path.
        """
        if self.config:
            try:
                return self.config.get("Processing", "interpreter")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_processing_processor(self):
        """
        Returns processing script path.
        """
        if self.config:
            try:
                return self.config.get("Processing", "processor")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None
            
    def get_vm_engine(self):
        """
        Returns virtualization engine.
        """
        if self.config:
            try:
                return self.config.get("VirtualMachines", "engine")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None
        
    def get_vm_mode(self):
        """
        Returns spawning mode for virtual machines.
        """
        if self.config:
            try:
                return self.config.get("VirtualMachines", "mode")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_vm_python(self):
        """
        Returns virtual machines Python path.
        """
        if self.config:
            try:
                return self.config.get("VirtualMachines", "python")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_vm_name(self, vm_id):
        """
        Returns virtual machine name for a given virtual machine ID.
        """
        if self.config:
            try:
                return self.config.get(vm_id, "name")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_vm_username(self, vm_id):
        """
        Returns username for a given virtual machine ID.
        """
        if self.config:
            try:
                return self.config.get(vm_id, "username")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_vm_password(self, vm_id):
        """
        Returns password for a given virtual machine ID.
        """
        if self.config:
            try:
                return self.config.get(vm_id, "password")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_vm_share(self, vm_id):
        """
        Returns shared folder for a given virtual machine ID.
        """
        if self.config:
            try:
                return self.config.get(vm_id, "share")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_vms(self):
        """
        Returns a lists all enabled virtual machines.
        """
        if self.config:
            try:
                return map(str.strip, self.config.get("VirtualMachines", "enabled").split(","))
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None
