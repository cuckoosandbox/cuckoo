// Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

rule embedded_macho
{
    strings:
        $magic1 = { ca fe ba be }
        $magic2 = { ce fa ed fe }
        $magic3 = { fe ed fa ce }
    condition:
        any of ($magic*) and not ($magic1 at 0) and not ($magic2 at 0) and not ($magic3 at 0)
}

rule embedded_pe
{
    strings:
        $a = "PE32"
        $b = "This program"
        $mz = { 4d 5a }
    condition:
        ($a or $b) and not ($mz at 0)
}

rule embedded_win_api
{
    strings:
        $mz = { 4d 5a }
        $api1 = "CreateFileA"
        $api2 = "GetProcAddress"
        $api3 = "LoadLibraryA"
        $api4 = "WinExec"
        $api5 = "GetSystemDirectoryA"
        $api6 = "WriteFile"
        $api7 = "ShellExecute"
        $api8 = "GetWindowsDirectory"
        $api9 = "URLDownloadToFile"
        $api10 = "IsBadReadPtr"
        $api11 = "IsBadWritePtr"
        $api12 = "SetFilePointer"
        $api13 = "GetTempPath"
        $api14 = "GetWindowsDirectory"
    condition:
        not ($mz at 0) and any of ($api*)
}
