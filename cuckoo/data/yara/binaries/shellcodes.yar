// Copyright (C) 2010-2014 Cuckoo Foundation.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

rule shellcode
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"

    strings:
        $mz = { 4d 5a }
        $shell1 = { 64 8b 64 }
        $shell2 = { 64 a1 30 }
        $shell3 = { 64 8b 15 30 }
        $shell4 = { 64 8b 35 30 }
        $shell5 = { 55 8b ec 83 c4 }
        $shell6 = { 55 8b ec 81 ec }
        $shell7 = { 55 8b ec e8 }
        $shell8 = { 55 8b ec e9 }
    condition:
        not ($mz at 0) and
        any of ($shell*)
}
