# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from cuckoo.processing.static import ELF


def test_elf_static_info():
    assert ELF("files/busybox-i686.elf").run() == {
        "file_header": {
            "abi_version": 0,
            "class": "ELF32",
            "data": "2's complement, little endian",
            "ei_version": "1 (current)",
            "entry_point_address": "0x08048168",
            "flags": "0x00000000",
            "machine": "Intel 80386",
            "magic": "\\x7fELF",
            "number_of_program_headers": 3,
            "number_of_section_headers": 13,
            "os_abi": "UNIX - System V",
            "section_header_string_table_index": 12,
            "size_of_program_headers": 32,
            "size_of_section_headers": 40,
            "size_of_this_header": 52,
            "start_of_program_headers": 52,
            "start_of_section_headers": 898052,
            "type": "EXEC (Executable file)",
            "version": "0x1"
        },
        "program_headers": [
            {"addr": "0x08048000", "flags": "R E", "size": 896994, "type": "LOAD"},
            {"addr": "0x08123000", "flags": "RW", "size": 19012, "type": "LOAD"},
            {"addr": "0x00000000", "flags": "RW", "size": 0, "type": "GNU_STACK"}
        ],
        "section_headers": [
            {"addr": "0x00000000", "name": "", "size": 0, "type": "NULL"},
            {"addr": "0x08048094", "name": ".init", "size": 28, "type": "PROGBITS"},
            {"addr": "0x080480b0", "name": ".text", "size": 721180, "type": "PROGBITS"},
            {"addr": "0x080f81cc", "name": ".fini", "size": 23, "type": "PROGBITS"},
            {"addr": "0x080f81f0", "name": ".rodata", "size": 175602, "type": "PROGBITS"},
            {"addr": "0x08123000", "name": ".eh_frame", "size": 4, "type": "PROGBITS"},
            {"addr": "0x08123004", "name": ".ctors", "size": 8, "type": "PROGBITS"},
            {"addr": "0x0812300c", "name": ".dtors", "size": 8, "type": "PROGBITS"},
            {"addr": "0x08123014", "name": ".jcr", "size": 4, "type": "PROGBITS"},
            {"addr": "0x08123018", "name": ".got.plt", "size": 12, "type": "PROGBITS"},
            {"addr": "0x08123024", "name": ".data", "size": 904, "type": "PROGBITS"},
            {"addr": "0x081233b0", "name": ".bss", "size": 18068, "type": "NOBITS"},
            {"addr": "0x00000000", "name": ".shstrtab", "size": 86, "type": "STRTAB"}
        ]
    }