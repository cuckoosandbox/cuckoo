# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import itertools
import logging
import random

from _winreg import HKEY_LOCAL_MACHINE, REG_SZ, REG_MULTI_SZ, REG_BINARY

from lib.common.abstracts import Auxiliary
from lib.common.rand import random_integer, random_string
from lib.common.registry import rename_regkey, regkey_exists
from lib.common.registry import set_regkey, query_value

log = logging.getLogger(__name__)

class Disguise(Auxiliary):
    """Disguise the analysis environment."""

    HDD_IDENTIFIERS = [
        "ST9160411AS",
    ]

    HDD_PATHS = [
        "IDE\\DiskST9160411AS_____________________________LV14____",
        "IDE\\DiskKINGSTON_SV300S_________________________541A____",
    ]

    CDROM_IDENTIFIERS = [
        "HL-DT-ST RW/DVD MU10N",
    ]

    SYSTEM_BIOS_DATES = [
        "03/11/11",
        "01/09/09",
    ]

    SYSTEM_BIOS_VERSIONS = [
        ["LENOVO - 3220", "Ver 1.00PARTTBL("],
        ["LENOVO - 2020", "Ver 1.00PARTTBLX"],
    ]

    VIDEO_BIOS_DATES = [
        "02/10/20",
        "06/12/20",
    ]

    VIDEO_BIOS_VERSIONS = [
        ["Hardware Version 0.0", "PARTTBLX"],
    ]

    BIOS_VERSIONS = [
        "6FET56WW (2.02 )",
        "7UET92WW (3.22 )",
    ]

    SYSTEM_MANUFACTURERS = [
        "LENOVO",
    ]

    SYSTEM_PRODUCTNAMES = [
        "64755N2",
        "2241W2U",
    ]

    def change_productid(self):
        """Randomize Windows ProductId.
        The Windows ProductId is occasionally used by malware
        to detect public setups of Cuckoo, e.g., Malwr.com.
        """
        value = "{0}-{1}-{2}-{3}".format(random_integer(5), random_integer(3),
                                         random_integer(7), random_integer(5))

        set_regkey(HKEY_LOCAL_MACHINE,
                   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                   "ProductId", REG_SZ, value)

    def patch_scsi_identifiers(self):
        types = {
            "DiskPeripheral": self.HDD_IDENTIFIERS,
            "CdRomPeripheral": self.CDROM_IDENTIFIERS,
        }

        for row in itertools.product([0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3]):
            type_ = query_value(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus %d\\Target Id %d\\Logical Unit Id %d" % row, "Type")
            value = query_value(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus %d\\Target Id %d\\Logical Unit Id %d" % row, "Identifier")
            if not type_ or not value:
                continue

            value = value.lower()
            if "vbox" in value or "vmware" in value or "qemu" in value or "virtual" in value:
                if type_ in types:
                    new_value = random.choice(types[type_])
                else:
                    log.warning("Unknown SCSI type (%s), disguising it with a random string", type_)
                    new_value = random_string(len(value))

                set_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus %d\\Target Id %d\\Logical Unit Id %d" % row,
                           "Identifier", REG_SZ, new_value)

    def patch_bios(self):
        set_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosDate", REG_SZ, random.choice(self.SYSTEM_BIOS_DATES))
        set_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion", REG_MULTI_SZ, random.choice(self.SYSTEM_BIOS_VERSIONS))
        set_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "VideoBiosDate", REG_SZ, random.choice(self.VIDEO_BIOS_DATES))
        set_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "VideoBiosVersion", REG_MULTI_SZ, random.choice(self.VIDEO_BIOS_VERSIONS))

    def patch_acpi(self):
        # TODO This should be improved, but for now may suffice.
        keywords = {
            "VBOX": "LNVO",
            "vbox": "lnvo",
            "VirtualBox": "LENOVOTP",
            "innotek GmbH": "",
        }

        regkeys = [
            ["SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", "AcpiData"],
            ["SYSTEM\\ControlSet001\\Services\\mssmbios\\Data", "AcpiData"],

            ["SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", "SMBiosData"],
            ["SYSTEM\\ControlSet001\\Services\\mssmbios\\Data", "SMBiosData"],
        ]

        for regkey, key in regkeys:
            value = query_value(HKEY_LOCAL_MACHINE, regkey, key)
            if value is None:
                continue

            for k, v in keywords.items():
                value = value.replace(k, v)

            set_regkey(HKEY_LOCAL_MACHINE, regkey, key, REG_BINARY, value)

        if regkey_exists(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__"):
            rename_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", "LENOVO")
            rename_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__", "LENOVO")
            rename_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\VBOX__", "LENOVO")

    def patch_processor(self):
        keywords = {
            "QEMU Virtual CPU version 2.0.0": "Intel(R) Core(TM) i7 CPU @3GHz",
        }

        for idx in xrange(32):
            value = query_value(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%d" % idx, "ProcessorNameString")
            if value is None:
                continue

            for k, v in keywords.items():
                value = value.replace(k, v)

            set_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%d" % idx,
                       "ProcessorNameString", REG_SZ, value)

    def patch_manufacturer(self):
        set_regkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\SystemInformation",
                   "BIOSVersion", REG_SZ, random.choice(self.BIOS_VERSIONS))
        set_regkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\SystemInformation",
                   "BIOSReleaseDate", REG_SZ, random.choice(self.SYSTEM_BIOS_DATES))
        set_regkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\SystemInformation",
                   "SystemManufacturer", REG_SZ, random.choice(self.SYSTEM_MANUFACTURERS))
        set_regkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\SystemInformation",
                   "SystemProductName", REG_SZ, random.choice(self.SYSTEM_PRODUCTNAMES))

    def patch_hdd_path(self):
        set_regkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
                   "0", REG_SZ, random.choice(self.HDD_PATHS))

    def start(self):
        self.change_productid()
        self.patch_scsi_identifiers()
        self.patch_bios()
        self.patch_acpi()
        self.patch_processor()
        self.patch_manufacturer()
        self.patch_hdd_path()
        return True
