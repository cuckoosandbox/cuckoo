# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from cuckoo.processing.static import ELF

def test_elf_static_info():
    assert ELF("tests/files/busybox-i686.elf").run() == {
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
            "version": "0x1",
        },
        "program_headers": [
            {"addr": "0x08048000", "flags": "R E", "size": 896994, "type": "LOAD"},
            {"addr": "0x08123000", "flags": "RW", "size": 19012, "type": "LOAD"},
            {"addr": "0x00000000", "flags": "RW", "size": 0, "type": "GNU_STACK"},
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
            {"addr": "0x00000000", "name": ".shstrtab", "size": 86, "type": "STRTAB"},
        ],
        "dynamic_tags": [],
        "notes": [],
        "relocations": [],
        "symbol_tables": [],
    }

def test_elf_static_info_tags():
    assert ELF("tests/files/ls-x86_64.elf").run()["dynamic_tags"] == [
        {"tag": "0x0000000000000001", "type": "NEEDED", "value": "Shared library: [libselinux.so.1]"},
        {"tag": "0x0000000000000001", "type": "NEEDED", "value": "Shared library: [libc.so.6]"},
        {"tag": "0x000000000000000c", "type": "INIT", "value": "0x00000000004022b8"},
        {"tag": "0x000000000000000d", "type": "FINI", "value": "0x0000000000413c8c"},
        {"tag": "0x0000000000000019", "type": "INIT_ARRAY", "value": "0x000000000061de00"},
        {"tag": "0x000000000000001b", "type": "INIT_ARRAYSZ", "value": "8 (bytes)"},
        {"tag": "0x000000000000001a", "type": "FINI_ARRAY", "value": "0x000000000061de08"},
        {"tag": "0x000000000000001c", "type": "FINI_ARRAYSZ", "value": "8 (bytes)"},
        {"tag": "0x000000006ffffef5", "type": "GNU_HASH", "value": "0x0000000000400298"},
        {"tag": "0x0000000000000005", "type": "STRTAB", "value": "0x0000000000401030"},
        {"tag": "0x0000000000000006", "type": "SYMTAB", "value": "0x0000000000400358"},
        {"tag": "0x000000000000000a", "type": "STRSZ", "value": "1500 (bytes)"},
        {"tag": "0x000000000000000b", "type": "SYMENT", "value": "24 (bytes)"},
        {"tag": "0x0000000000000015", "type": "DEBUG", "value": "0x0000000000000000"},
        {"tag": "0x0000000000000003", "type": "PLTGOT", "value": "0x000000000061e000"},
        {"tag": "0x0000000000000002", "type": "PLTRELSZ", "value": "2688 (bytes)"},
        {"tag": "0x0000000000000014", "type": "PLTREL", "value": "RELA"},
        {"tag": "0x0000000000000017", "type": "JMPREL", "value": "0x0000000000401838"},
        {"tag": "0x0000000000000007", "type": "RELA", "value": "0x0000000000401790"},
        {"tag": "0x0000000000000008", "type": "RELASZ", "value": "168 (bytes)"},
        {"tag": "0x0000000000000009", "type": "RELAENT", "value": "24 (bytes)"},
        {"tag": "0x000000006ffffffe", "type": "VERNEED", "value": "0x0000000000401720"},
        {"tag": "0x000000006fffffff", "type": "VERNEEDNUM", "value": "1"},
        {"tag": "0x000000006ffffff0", "type": "VERSYM", "value": "0x000000000040160c"},
        {"tag": "0x0000000000000000", "type": "NULL", "value": "0x0000000000000000"},
    ]

def test_elf_static_info_symbols():
    assert ELF("tests/files/ls-x86_64.elf").run()["symbol_tables"] == [
        {"bind": "LOCAL", "ndx_name": "", "type": "NOTYPE", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__ctype_toupper_loc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__uflow", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getenv", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "sigprocmask", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "raise", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "localtime", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__mempcpy_chk", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "abort", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__errno_location", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strncmp", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "WEAK", "ndx_name": "_ITM_deregisterTMCloneTable", "type": "NOTYPE", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "_exit", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strcpy", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__fpending", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "isatty", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "sigaction", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "iswcntrl", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "wcswidth", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "localeconv", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "mbstowcs", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "readlink", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "clock_gettime", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "setenv", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "textdomain", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fclose", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "opendir", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getpwuid", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "bindtextdomain", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "stpcpy", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "dcgettext", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__ctype_get_mb_cur_max", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strlen", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__lxstat", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__stack_chk_fail", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getopt_long", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "mbrtowc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strchr", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getgrgid", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__overflow", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strrchr", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fgetfilecon", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "gmtime_r", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "lseek", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "gettimeofday", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__assert_fail", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__strtoul_internal", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fnmatch", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "memset", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fscanf", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "ioctl", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "close", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "closedir", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__libc_start_main", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "memcmp", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "_setjmp", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fputs_unlocked", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "calloc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "lgetfilecon", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strcmp", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "signal", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "dirfd", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getpwnam", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__memcpy_chk", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "sigemptyset", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "WEAK", "ndx_name": "__gmon_start__", "type": "NOTYPE", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "memcpy", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getgrnam", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getfilecon", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "tzset", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fileno", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "tcgetpgrp", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__xstat", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "readdir", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "wcwidth", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fflush", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "nl_langinfo", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "ungetc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__fxstat", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strcoll", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__freading", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fwrite_unlocked", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "realloc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "stpncpy", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fdopen", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "setlocale", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__printf_chk", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "timegm", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strftime", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "mempcpy", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "memmove", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "error", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "open", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fseeko", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "WEAK", "ndx_name": "_Jv_RegisterClasses", "type": "NOTYPE", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "unsetenv", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strtoul", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__cxa_atexit", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "wcstombs", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "getxattr", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "freecon", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "sigismember", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "exit", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fwrite", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__fprintf_chk", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "WEAK", "ndx_name": "_ITM_registerTMCloneTable", "type": "NOTYPE", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "fflush_unlocked", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "mbsinit", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "iswprint", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "sigaddset", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "strstr", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__ctype_tolower_loc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__ctype_b_loc", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__sprintf_chk", "type": "FUNC", "value": "0x0000000000000000"},
        {"bind": "GLOBAL", "ndx_name": "__progname", "type": "OBJECT", "value": "0x000000000061e600"},
        {"bind": "GLOBAL", "ndx_name": "_fini", "type": "FUNC", "value": "0x0000000000413c8c"},
        {"bind": "GLOBAL", "ndx_name": "optind", "type": "OBJECT", "value": "0x000000000061e610"},
        {"bind": "GLOBAL", "ndx_name": "_init", "type": "FUNC", "value": "0x00000000004022b8"},
        {"bind": "GLOBAL", "ndx_name": "free", "type": "FUNC", "value": "0x0000000000402340"},
        {"bind": "WEAK", "ndx_name": "program_invocation_name", "type": "OBJECT", "value": "0x000000000061e620"},
        {"bind": "GLOBAL", "ndx_name": "__bss_start", "type": "NOTYPE", "value": "0x000000000061e600"},
        {"bind": "GLOBAL", "ndx_name": "_end", "type": "NOTYPE", "value": "0x000000000061f368"},
        {"bind": "GLOBAL", "ndx_name": "__progname_full", "type": "OBJECT", "value": "0x000000000061e620"},
        {"bind": "GLOBAL", "ndx_name": "_obstack_memory_used", "type": "FUNC", "value": "0x0000000000412960"},
        {"bind": "GLOBAL", "ndx_name": "obstack_alloc_failed_handler", "type": "OBJECT", "value": "0x000000000061e5f8"},
        {"bind": "GLOBAL", "ndx_name": "_obstack_begin", "type": "FUNC", "value": "0x0000000000412780"},
        {"bind": "GLOBAL", "ndx_name": "_edata", "type": "NOTYPE", "value": "0x000000000061e600"},
        {"bind": "GLOBAL", "ndx_name": "stderr", "type": "OBJECT", "value": "0x000000000061e640"},
        {"bind": "GLOBAL", "ndx_name": "_obstack_free", "type": "FUNC", "value": "0x00000000004128f0"},
        {"bind": "WEAK", "ndx_name": "program_invocation_short_name", "type": "OBJECT", "value": "0x000000000061e600"},
        {"bind": "GLOBAL", "ndx_name": "localtime_r", "type": "FUNC", "value": "0x00000000004023a0"},
        {"bind": "GLOBAL", "ndx_name": "_obstack_allocated_p", "type": "FUNC", "value": "0x00000000004128c0"},
        {"bind": "GLOBAL", "ndx_name": "optarg", "type": "OBJECT", "value": "0x000000000061e618"},
        {"bind": "GLOBAL", "ndx_name": "_obstack_begin_1", "type": "FUNC", "value": "0x00000000004127a0"},
        {"bind": "GLOBAL", "ndx_name": "_obstack_newchunk", "type": "FUNC", "value": "0x00000000004127c0"},
        {"bind": "GLOBAL", "ndx_name": "malloc", "type": "FUNC", "value": "0x0000000000402790"},
        {"bind": "GLOBAL", "ndx_name": "stdout", "type": "OBJECT", "value": "0x000000000061e608"},
    ]

def test_elf_static_info_notes():
    assert ELF("tests/files/ls-x86_64.elf").run()["notes"] == [
        {
            "name": "GNU",
            "note": "NT_GNU_ABI_TAG (ABI version tag)\n" +
                    "    OS: Linux, ABI: 2.6.32",
            "owner": "GNU",
            "size": "0x0000000000000010"
        },
        {
            "name": "GNU",
            "note": "NT_GNU_BUILD_ID (unique build ID bitstring)\n" +
                    "    Build ID: eca98eeadafddff44caf37ae3d4b227132861218",
            "owner": "GNU",
            "size": "0x0000000000000014",
        },
    ]

def test_elf_static_info_relocations():
    assert ELF("tests/files/ls-x86_64.elf").run()["relocations"] == [
        {
            "name": ".rela.dyn",
            "entries": [
                {
                    "info": "0x0000004100000006",
                    "name": "__gmon_start__",
                    "offset": "0x000000000061dff8",
                    "type": "R_X86_64_GLOB_DAT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000007200000005",
                    "name": "__progname",
                    "offset": "0x000000000061e600",
                    "type": "R_X86_64_COPY",
                    "value": "0x000000000061e600"
                },
                {
                    "info": "0x0000008800000005",
                    "name": "stdout",
                    "offset": "0x000000000061e608",
                    "type": "R_X86_64_COPY",
                    "value": "0x000000000061e608"
                },
                {
                    "info": "0x0000007400000005",
                    "name": "optind",
                    "offset": "0x000000000061e610",
                    "type": "R_X86_64_COPY",
                    "value": "0x000000000061e610"
                },
                {
                    "info": "0x0000008400000005",
                    "name": "optarg",
                    "offset": "0x000000000061e618",
                    "type": "R_X86_64_COPY",
                    "value": "0x000000000061e618"
                },
                {
                    "info": "0x0000007a00000005",
                    "name": "__progname_full",
                    "offset": "0x000000000061e620",
                    "type": "R_X86_64_COPY",
                    "value": "0x000000000061e620"
                },
                {
                    "info": "0x0000007f00000005",
                    "name": "stderr",
                    "offset": "0x000000000061e640",
                    "type": "R_X86_64_COPY",
                    "value": "0x000000000061e640"
                }
            ],
        },
        {
            "name": ".rela.plt",
            "entries": [
                {
                    "info": "0x0000000100000007",
                    "name": "__ctype_toupper_loc",
                    "offset": "0x000000000061e018",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000200000007",
                    "name": "__uflow",
                    "offset": "0x000000000061e020",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000300000007",
                    "name": "getenv",
                    "offset": "0x000000000061e028",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000400000007",
                    "name": "sigprocmask",
                    "offset": "0x000000000061e030",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000500000007",
                    "name": "raise",
                    "offset": "0x000000000061e038",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000007600000007",
                    "name": "free",
                    "offset": "0x000000000061e040",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000402340"
                },
                {
                    "info": "0x0000000600000007",
                    "name": "localtime",
                    "offset": "0x000000000061e048",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000700000007",
                    "name": "__mempcpy_chk",
                    "offset": "0x000000000061e050",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000800000007",
                    "name": "abort",
                    "offset": "0x000000000061e058",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000900000007",
                    "name": "__errno_location",
                    "offset": "0x000000000061e060",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000a00000007",
                    "name": "strncmp",
                    "offset": "0x000000000061e068",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000008200000007",
                    "name": "localtime_r",
                    "offset": "0x000000000061e070",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x00000000004023a0"
                },
                {
                    "info": "0x0000000c00000007",
                    "name": "_exit",
                    "offset": "0x000000000061e078",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000d00000007",
                    "name": "strcpy",
                    "offset": "0x000000000061e080",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000e00000007",
                    "name": "__fpending",
                    "offset": "0x000000000061e088",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000000f00000007",
                    "name": "isatty",
                    "offset": "0x000000000061e090",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001000000007",
                    "name": "sigaction",
                    "offset": "0x000000000061e098",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001100000007",
                    "name": "iswcntrl",
                    "offset": "0x000000000061e0a0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001200000007",
                    "name": "wcswidth",
                    "offset": "0x000000000061e0a8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001300000007",
                    "name": "localeconv",
                    "offset": "0x000000000061e0b0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001400000007",
                    "name": "mbstowcs",
                    "offset": "0x000000000061e0b8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001500000007",
                    "name": "readlink",
                    "offset": "0x000000000061e0c0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001600000007",
                    "name": "clock_gettime",
                    "offset": "0x000000000061e0c8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001700000007",
                    "name": "setenv",
                    "offset": "0x000000000061e0d0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001800000007",
                    "name": "textdomain",
                    "offset": "0x000000000061e0d8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001900000007",
                    "name": "fclose",
                    "offset": "0x000000000061e0e0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001a00000007",
                    "name": "opendir",
                    "offset": "0x000000000061e0e8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001b00000007",
                    "name": "getpwuid",
                    "offset": "0x000000000061e0f0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001c00000007",
                    "name": "bindtextdomain",
                    "offset": "0x000000000061e0f8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001d00000007",
                    "name": "stpcpy",
                    "offset": "0x000000000061e100",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001e00000007",
                    "name": "dcgettext",
                    "offset": "0x000000000061e108",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000001f00000007",
                    "name": "__ctype_get_mb_cur_max",
                    "offset": "0x000000000061e110",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002000000007",
                    "name": "strlen",
                    "offset": "0x000000000061e118",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002100000007",
                    "name": "__lxstat",
                    "offset": "0x000000000061e120",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002200000007",
                    "name": "__stack_chk_fail",
                    "offset": "0x000000000061e128",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002300000007",
                    "name": "getopt_long",
                    "offset": "0x000000000061e130",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002400000007",
                    "name": "mbrtowc",
                    "offset": "0x000000000061e138",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002500000007",
                    "name": "strchr",
                    "offset": "0x000000000061e140",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002600000007",
                    "name": "getgrgid",
                    "offset": "0x000000000061e148",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002700000007",
                    "name": "__overflow",
                    "offset": "0x000000000061e150",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002800000007",
                    "name": "strrchr",
                    "offset": "0x000000000061e158",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002900000007",
                    "name": "fgetfilecon",
                    "offset": "0x000000000061e160",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002a00000007",
                    "name": "gmtime_r",
                    "offset": "0x000000000061e168",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002b00000007",
                    "name": "lseek",
                    "offset": "0x000000000061e170",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002c00000007",
                    "name": "gettimeofday",
                    "offset": "0x000000000061e178",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002d00000007",
                    "name": "__assert_fail",
                    "offset": "0x000000000061e180",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002e00000007",
                    "name": "__strtoul_internal",
                    "offset": "0x000000000061e188",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000002f00000007",
                    "name": "fnmatch",
                    "offset": "0x000000000061e190",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003000000007",
                    "name": "memset",
                    "offset": "0x000000000061e198",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003100000007",
                    "name": "fscanf",
                    "offset": "0x000000000061e1a0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003200000007",
                    "name": "ioctl",
                    "offset": "0x000000000061e1a8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003300000007",
                    "name": "close",
                    "offset": "0x000000000061e1b0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003400000007",
                    "name": "closedir",
                    "offset": "0x000000000061e1b8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003500000007",
                    "name": "__libc_start_main",
                    "offset": "0x000000000061e1c0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003600000007",
                    "name": "memcmp",
                    "offset": "0x000000000061e1c8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003700000007",
                    "name": "_setjmp",
                    "offset": "0x000000000061e1d0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003800000007",
                    "name": "fputs_unlocked",
                    "offset": "0x000000000061e1d8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003900000007",
                    "name": "calloc",
                    "offset": "0x000000000061e1e0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003a00000007",
                    "name": "lgetfilecon",
                    "offset": "0x000000000061e1e8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003b00000007",
                    "name": "strcmp",
                    "offset": "0x000000000061e1f0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003c00000007",
                    "name": "signal",
                    "offset": "0x000000000061e1f8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003d00000007",
                    "name": "dirfd",
                    "offset": "0x000000000061e200",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003e00000007",
                    "name": "getpwnam",
                    "offset": "0x000000000061e208",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000003f00000007",
                    "name": "__memcpy_chk",
                    "offset": "0x000000000061e210",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004000000007",
                    "name": "sigemptyset",
                    "offset": "0x000000000061e218",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004200000007",
                    "name": "memcpy",
                    "offset": "0x000000000061e220",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004300000007",
                    "name": "getgrnam",
                    "offset": "0x000000000061e228",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004400000007",
                    "name": "getfilecon",
                    "offset": "0x000000000061e230",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004500000007",
                    "name": "tzset",
                    "offset": "0x000000000061e238",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004600000007",
                    "name": "fileno",
                    "offset": "0x000000000061e240",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004700000007",
                    "name": "tcgetpgrp",
                    "offset": "0x000000000061e248",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004800000007",
                    "name": "__xstat",
                    "offset": "0x000000000061e250",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004900000007",
                    "name": "readdir",
                    "offset": "0x000000000061e258",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004a00000007",
                    "name": "wcwidth",
                    "offset": "0x000000000061e260",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000008700000007",
                    "name": "malloc",
                    "offset": "0x000000000061e268",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000402790"
                },
                {
                    "info": "0x0000004b00000007",
                    "name": "fflush",
                    "offset": "0x000000000061e270",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004c00000007",
                    "name": "nl_langinfo",
                    "offset": "0x000000000061e278",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004d00000007",
                    "name": "ungetc",
                    "offset": "0x000000000061e280",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004e00000007",
                    "name": "__fxstat",
                    "offset": "0x000000000061e288",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000004f00000007",
                    "name": "strcoll",
                    "offset": "0x000000000061e290",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005000000007",
                    "name": "__freading",
                    "offset": "0x000000000061e298",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005100000007",
                    "name": "fwrite_unlocked",
                    "offset": "0x000000000061e2a0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005200000007",
                    "name": "realloc",
                    "offset": "0x000000000061e2a8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005300000007",
                    "name": "stpncpy",
                    "offset": "0x000000000061e2b0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005400000007",
                    "name": "fdopen",
                    "offset": "0x000000000061e2b8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005500000007",
                    "name": "setlocale",
                    "offset": "0x000000000061e2c0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005600000007",
                    "name": "__printf_chk",
                    "offset": "0x000000000061e2c8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005700000007",
                    "name": "timegm",
                    "offset": "0x000000000061e2d0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005800000007",
                    "name": "strftime",
                    "offset": "0x000000000061e2d8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005900000007",
                    "name": "mempcpy",
                    "offset": "0x000000000061e2e0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005a00000007",
                    "name": "memmove",
                    "offset": "0x000000000061e2e8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005b00000007",
                    "name": "error",
                    "offset": "0x000000000061e2f0",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005c00000007",
                    "name": "open",
                    "offset": "0x000000000061e2f8",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005d00000007",
                    "name": "fseeko",
                    "offset": "0x000000000061e300",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000005f00000007",
                    "name": "unsetenv",
                    "offset": "0x000000000061e308",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006000000007",
                    "name": "strtoul",
                    "offset": "0x000000000061e310",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006100000007",
                    "name": "__cxa_atexit",
                    "offset": "0x000000000061e318",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006200000007",
                    "name": "wcstombs",
                    "offset": "0x000000000061e320",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006300000007",
                    "name": "getxattr",
                    "offset": "0x000000000061e328",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006400000007",
                    "name": "freecon",
                    "offset": "0x000000000061e330",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006500000007",
                    "name": "sigismember",
                    "offset": "0x000000000061e338",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006600000007",
                    "name": "exit",
                    "offset": "0x000000000061e340",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006700000007",
                    "name": "fwrite",
                    "offset": "0x000000000061e348",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006800000007",
                    "name": "__fprintf_chk",
                    "offset": "0x000000000061e350",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006a00000007",
                    "name": "fflush_unlocked",
                    "offset": "0x000000000061e358",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006b00000007",
                    "name": "mbsinit",
                    "offset": "0x000000000061e360",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006c00000007",
                    "name": "iswprint",
                    "offset": "0x000000000061e368",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006d00000007",
                    "name": "sigaddset",
                    "offset": "0x000000000061e370",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006e00000007",
                    "name": "strstr",
                    "offset": "0x000000000061e378",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000006f00000007",
                    "name": "__ctype_tolower_loc",
                    "offset": "0x000000000061e380",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000007000000007",
                    "name": "__ctype_b_loc",
                    "offset": "0x000000000061e388",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
                {
                    "info": "0x0000007100000007",
                    "name": "__sprintf_chk",
                    "offset": "0x000000000061e390",
                    "type": "R_X86_64_JUMP_SLOT",
                    "value": "0x0000000000000000"
                },
            ],
        },
    ]
