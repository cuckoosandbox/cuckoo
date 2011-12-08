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


class CuckooDict(dict):
    """
    This class key separated by points dict.
    """

    def __init__(self):
        pass

    def __getattr__(self, item):
        """
        Maps values to attributes. Only called if there isn't an attribute with this name.
        @param item: key to be fetched 
        """

        try:
            return self.__getitem__(item)
        except KeyError:
            raise Exception, "Unable to access '%s'" % item

    def __setattr__(self, item, value):
        """
        Maps attributes to values
        @param item: key
        @param valure: value 
        """

        if not self.__dict__.has_key('_AttribDict__initialised'):
            return dict.__setattr__(self, item, value)
        elif self.__dict__.has_key(item):
            dict.__setattr__(self, item, value)
        else:
            self.__setitem__(item, value)

    def __missing__(self, key):
        """
        Creates nested dicts if a key not exist.
        """
        value = CuckooDict()
        self[key] = value
        return value
     
    
# Initialize Cuckoo analysis knowledge base.
kb = CuckooDict()