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

import string

def convert_char(c):
    """
    Converts a character in a printable format.
    @param char: char to be converted 
    @return: printable character
    """
    if c in string.ascii_letters or \
       c in string.digits or \
       c in string.punctuation or \
       c in string.whitespace:
        return c
    else:
        return r'\x%02x' % ord(c)

def convert_to_printable(s):
    """
    Converts a string in a printable format.
    @param s: string to be converted 
    @return: printable string
    """
    return ''.join([convert_char(c) for c in s])