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


class GuestManager():
    """Describe a generic interface to manage analysis virtual machine."""
    
    def __init__(self, address, user, password):
        """Creates a new manager.
        @param address = guest IP address
        @param user: valid user on guest
        @param password: plaintext password
        """  
        self._address = address
        self._user = user
        self._password = password
        self._agent_path = None  # Random path where cuckoo agent is placed.
    
    def start_analysis(self, sample):
        """Start analysis inside guest.
        @param sample: sample to be uploaded to guest
        @raise NotImplementedError: if method not implemented
        """
        raise NotImplementedError
    
    def get_results(self):
        """Gets analysis results from guest.
        @raise NotImplementedError: if method not implemented
        """
        raise NotImplementedError