rule LnkHeader {
    strings:
        $signature = { 4c 00 00 00 }
        $guid = { 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

    condition:
        $signature at 0 and $guid at 4
}
