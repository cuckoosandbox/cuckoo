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

def color(t, c):
    """
    Colorize text.
    @param t: text
    @param c: color
    """ 
    return chr(0x1b)+"["+str(c)+"m"+t+chr(0x1b)+"[0m"

def black(t):
    """
    Colorize black
    @param t:  text
    """
    return color(t, 30)

def red(t):
    """
    Colorize red
    @param t:  text
    """
    return color(t, 31)

def green(t):
    """
    Colorize green
    @param t:  text
    """
    return color(t, 32)

def yellow(t):
    """
    Colorize yellow
    @param t:  text
    """
    return color(t, 33)

def blue(t):
    """
    Colorize blue
    @param t:  text
    """
    return color(t, 34)

def magenta(t):
    """
    Colorize magenta
    @param t:  text
    """
    return color(t, 35)

def cyan(t):
    """
    Colorize cyan
    @param t:  text
    """
    return color(t, 36)

def white(t):
    """
    Colorize white
    @param t:  text
    """
    return color(t, 37)

def bold(t):
    """
    Bolder text
    @param t: text
    """ 
    return color(t, 1)
