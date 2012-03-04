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

# Version
CUCKOO_VERSION = "v0.3.3-dev"

# Paths
CUCKOO_LOG_FILE = "log/cuckoo.log"
CUCKOO_DB_FILE = "db/cuckoo.db"
CUCKOO_CONFIG_FILE = "conf/cuckoo.conf"
CUCKOO_REPORTING_CONFIG_FILE = "conf/reporting.conf"

# Errors
CUCKOO_ERROR_DUPLICATE_TASK = "Cuckoo Operational Error: task already exists"
CUCKOO_ERROR_TARGET_NOT_FOUND = "Cuckoo Operational Error: target file does not exist"
CUCKOO_ERROR_INVALID_TARGET = "Cuckoo Operational Error: the target path is invalid"
CUCKOO_ERROR_INVALID_TARGET_FILE_TYPE = "Cuckoo Operational Error: the target file's type is not supported"
CUCKOO_ERROR_VM_NOT_FOUND = "Cuckoo Operational Error: cannot find the selected virtual machine"
CUCKOO_ERROR_VM_ACQUISITION_FAILED = "Cuckoo Operational Error: cannot acquire handle to the selected virtual machine"
CUCKOO_ERROR_SHARED_FOLDER_NOT_FOUND = "Cuckoo Operational Error: the selected shared folder does not exist"
CUCKOO_ERROR_CANNOT_COPY_TARGET_FILE = "Cuckoo Operational Error: cannot copy the original target file"
CUCKOO_ERROR_VM_RESTORE_FAILED = "Cuckoo Operational Error: failed to restore the selected virtual machine's snapshot"
CUCKOO_ERROR_VM_START_FAILED = "Cuckoo Operational Error: failed to start the selected virtual machine"
CUCKOO_ERROR_RESULTS_PATH_NOT_FOUND = "Cuckoo Operational Error: the analysis results folder does not exist"