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

import unittest

import data

class TestCuckooDict(unittest.TestCase):

    def setUp(self):
        self.d = data.CuckooDict()
        
    def testAssignStr(self):
        self.d.a = "a"
        self.assertEqual(self.d.a, "a")
        self.assertEqual(type(self.d.a), str)
        self.d.b.a = "a"
        self.assertEqual(self.d.b.a, "a")
        self.assertEqual(type(self.d.b.a), str)

    def testAssignInt(self):
        self.d.c = 2
        self.assertEqual(self.d.c, 2)
        self.assertEqual(type(self.d.c), int)
        self.d.b.c = 2
        self.assertEqual(self.d.b.c, 2)
        self.assertEqual(type(self.d.b.c), int)
    
    def testAssignArray(self):
        ar = [1,2,3,"a"]
        self.d.d = ar
        self.assertEqual(self.d.d, ar)
        self.assertEqual(type(self.d.d), list)
        self.assertEqual(len(self.d.d), 4)
        self.d.b.d = ar 
        self.assertEqual(self.d.b.d, ar)
        self.assertEqual(type(self.d.b.d), list)    
        self.assertEqual(len(self.d.b.d), 4)   
        
    def testAssignHash(self):
        h = {}
        h['a'] = 1
        h[3] = '22'
        self.d.e = h
        self.assertEqual(self.d.e, h)
        self.assertEqual(type(self.d.e), dict)
        self.assertEqual(len(self.d.e), 2)
        self.d.b.e = h 
        self.assertEqual(self.d.b.e, h)
        self.assertEqual(type(self.d.b.e), dict)    
        self.assertEqual(len(self.d.b.e), 2)  
        
    def testFor(self):
        h = {}
        h['a'] = 'a'
        h['b'] = 'b'
        self.d.h = h
        for k,v in self.d.h.items():
            self.assertEqual(type(v), str)
        self.assertEqual(len(self.d.h.items()), 2)
        self.d.i.a = "a"
        self.d.i.b = "b"
        for k,v in self.d.i.items():
            self.assertEqual(type(v), str)
        self.assertEqual(len(self.d.i.items()), 2)
        
        
if __name__ == '__main__':
    unittest.main()