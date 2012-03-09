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

import sys
import random

from cuckoo.common.constants import CUCKOO_VERSION

def color(t, c):
    if sys.platform == "win32":
        return t

    return chr(0x1b)+"["+str(c)+"m"+t+chr(0x1b)+"[0m"

def logo():
    """
    Prints a random Cuckoo Sandbox logo.
    """
    logos = []

    logos.append("""
                           >=>                            
                           >=>                            
     >==> >=>  >=>    >==> >=>  >=>    >=>        >=>     
   >=>    >=>  >=>  >=>    >=> >=>   >=>  >=>   >=>  >=>  
  >=>     >=>  >=> >=>     >=>=>    >=>    >=> >=>    >=> 
   >=>    >=>  >=>  >=>    >=> >=>   >=>  >=>   >=>  >=>  
     >==>   >==>=>    >==> >=>  >=>    >=>        >=>""")

    logos.append("""
                      \\                  
    ___  ,   .   ___  |   ,   __.    __. 
  .'   ` |   | .'   ` |  /  .'   \ .'   \\
  |      |   | |      |-<   |    | |    |
   `._.' `._/|  `._.' /  \\_  `._.'  `._.'""")

    logos.append("""
  01100011 01110101 01100011 01101011 01101111 01101111""")

    logos.append("""
                                 _|                            
     _|_|_|  _|    _|    _|_|_|  _|  _|      _|_|      _|_|    
   _|        _|    _|  _|        _|_|      _|    _|  _|    _|  
   _|        _|    _|  _|        _|  _|    _|    _|  _|    _|  
     _|_|_|    _|_|_|    _|_|_|  _|    _|    _|_|      _|_|""")

    logos.append("""
                      __                  
  .----..--.--..----.|  |--..-----..-----.
  |  __||  |  ||  __||    < |  _  ||  _  |
  |____||_____||____||__|__||_____||_____|""")

    logos.append("""
                          .:                 
                          ::                 
    .-.     ,  :   .-.    ;;.-.  .-.   .-.   
   ;       ;   ;  ;       ;; .' ;   ;';   ;' 
   `;;;;'.'`..:;._`;;;;'_.'`  `.`;;'  `;;'""")

    logos.append("""
  eeee e   e eeee e   e  eeeee eeeee 
  8  8 8   8 8  8 8   8  8  88 8  88 
  8e   8e  8 8e   8eee8e 8   8 8   8 
  88   88  8 88   88   8 8   8 8   8 
  88e8 88ee8 88e8 88   8 8eee8 8eee8""")

    logos.append("""
  _____________________________________/\/\_______________________________
  ___/\/\/\/\__/\/\__/\/\____/\/\/\/\__/\/\__/\/\____/\/\/\______/\/\/\___
  _/\/\________/\/\__/\/\__/\/\________/\/\/\/\____/\/\__/\/\__/\/\__/\/\_
  _/\/\________/\/\__/\/\__/\/\________/\/\/\/\____/\/\__/\/\__/\/\__/\/\_
  ___/\/\/\/\____/\/\/\/\____/\/\/\/\__/\/\__/\/\____/\/\/\______/\/\/\___
  ________________________________________________________________________""")

    logos.append("""
   _______ _     _ _______ _     _  _____   _____ 
   |       |     | |       |____/  |     | |     |
   |_____  |_____| |_____  |    \\_ |_____| |_____|""")

    logos.append("""
                     _ 
    ____ _   _  ____| |  _ ___   ___
   / ___) | | |/ ___) |_/ ) _ \ / _ \\
  ( (___| |_| ( (___|  _ ( |_| | |_| |
   \\____)____/ \\____)_| \\_)___/ \\___/""")

    logos.append("""
                               ),-.     /
  Cuckoo Sandbox              <(a  `---',' 
     no chance for malwares!  ( `-, ._> )
                               ) _>.___/
                                   _/""")

    logos.append("""
  .-----------------.
  | Cuckoo Sandbox? |   \\
  |     OH NOES!    |\\  '-.__.-'   
  '-----------------' \\  /oo |--.--,--,--.
                         \\_.-'._i__i__i_.'
                               \"\"\"\"\"\"\"\"\"""")

    print(color(random.choice(logos), random.randrange(31, 37)))
    print
    print(" Cuckoo Sandbox %s" % color(CUCKOO_VERSION, 33))
    print(" www.cuckoobox.org")
    print(" Copyright (c) 2010-2012")
    print

