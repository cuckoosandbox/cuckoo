#!/usr/bin/python
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
import ConfigParser

from cuckoo.core.colors import *

CONFIG_FILE = "cuckoo.conf"

class CuckooConfig:
    def __init__(self):
        self.config = None

        if os.path.exists(CONFIG_FILE):
            try:
                self.config = ConfigParser.ConfigParser()
                self.config.read(CONFIG_FILE)
            except Exception, why:
                print(red("[Config] [ERROR] Cannot read config file \"%s\": %s."
                    % (CONFIG_FILE, why)))
                sys.exit(-1)
        else:
            print(red("[Config] [ERROR] Cannot find config file \"%s\"."
                % CONFIG_FILE))
            sys.exit(-1)

    def _error_parse(self, why):
        print(red("[Config] [ERROR] Error parsing config file: \"%s\": %s."
                    % (CONFIG_FILE, why)))

    def _error_config(self):
        print(red("[Config] [ERROR] ConfigParser not properly initialized."))

    def get_host_interface(self):
        if self.config:
            try:
                return self.config.get("Host", "interface")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_logging_path(self):
        if self.config:
            try:
                return self.config.get("Logging", "path")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_logging_utc(self):
        if self.config:
            try:
                return self.config.get("Logging", "utc")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_logging_debug(self):
        if self.config:
            try:
                return self.config.get("Logging", "debug")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None

    def get_analysis_watchdog_timeout(self):
        if self.config:
            try:
                return self.config.get("Analysis", "watchdog_timeout")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_analysis_analysis_timeout(self):
        if self.config:
            try:
                return self.config.get("Analysis", "analysis_timeout")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_analysis_results_path(self):
        if self.config:
            try:
                return self.config.get("Analysis", "results_path")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_analysis_processor(self):
        if self.config:
            try:
                return self.config.get("Analysis", "postprocessing")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            return None

    def get_localdb(self):
        if self.config:
            try:
                return self.config.get("LocalDatabase", "file")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None
            
    def get_vm_engine(self):
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
        if self.config:
            try:
                return self.config.get("VirtualMachines", "enabled").split(",")
            except Exception, why:
                self._error_parse(why)
                return None
        else:
            self._error_config()
            return None
