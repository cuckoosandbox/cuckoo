// Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

rule shellcode
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"

    strings:
        $a = { 64 8b 64 }
        $b = { 64 a1 30 }
        $c = { 64 8b 15 30 }
        $d = { 64 8b 35 30 }
        $e = { 55 8b ec 83 c4 }
        $f = { 55 8b ec 81 ec }
        $g = { 55 8b ec e8 }
        $h = { 55 8b ec e9 }
    condition:
        any of them
}
