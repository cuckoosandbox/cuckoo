# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import datetime

from cuckoo.processing.platform.linux import StapParser, LinuxSystemTap

def test_staplog():
    assert list(StapParser(open("tests/files/log.stap"))) == [{
        "api": "execve",
        "arguments": {
            "p0": "/usr/bin/sh",
            "p1": ["sh", "-c", "/tmp/helloworld.sh"],
            "p2": [
                "LANGUAGE=en_US:en",
                "HOME=/root",
                "LOGNAME=root",
                "PATH=/usr/bin:/bin",
                "LANG=en_US.UTF-8",
                "SHELL=/bin/sh",
                "PWD=/root"
            ],
        },
        "instruction_pointer": "b774dcf9",
        "pid": 680,
        "process_name": "python",
        "raw": "Mon Jun 19 16:58:31 2017.445170 python@b774dcf9[680] execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"/tmp/helloworld.sh\"], [\"LANGUAGE=en_US:en\", \"HOME=/root\", \"LOGNAME=root\", \"PATH=/usr/bin:/bin\", \"LANG=en_US.UTF-8\", \"SHELL=/bin/sh\", \"PWD=/root\"]) = -2 (ENOENT)\n",
        "return_value": "-2",
        "status": "ENOENT",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 445170),
        "type": "apicall",
    }, {
        "api": "brk",
        "arguments": {
            "p0": "0x0"
        },
        "instruction_pointer": "b77825f7",
        "pid": 680,
        "process_name": "sh",
        "raw": "Mon Jun 19 16:58:31 2017.517266 sh@b77825f7[680] brk(0x0) = -2118402048\n",
        "return_value": "-2118402048",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 517266),
        "type": "apicall",
    }, {
        "api": "access",
        "arguments": {
            "p0": "/etc/ld.so.nohwcap",
            "p1": "F_OK"
        },
        "instruction_pointer": "b77838c1",
        "pid": 680,
        "process_name": "sh",
        "raw": "Mon Jun 19 16:58:31 2017.521264 sh@b77838c1[680] access(\"/etc/ld.so.nohwcap\", F_OK) = -2 (ENOENT)\n",
        "return_value": "-2",
        "status": "ENOENT",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 521264),
        "type": "apicall",
    }, {
        "api": "mmap2",
        "arguments": {
            "p0": "0x0",
            "p1": "12288",
            "p2": "PROT_READ|PROT_WRITE",
            "p3": "MAP_PRIVATE|MAP_ANONYMOUS",
            "p4": "-1",
            "p5": "0",
        },
        "instruction_pointer": "b7783970",
        "pid": 680,
        "process_name": "sh",
        "raw": "Mon Jun 19 16:58:31 2017.550890 sh@b7783970[680] mmap2(0x0, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7764000\n",
        "return_value": "0xb7764000",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 550890),
        "type": "apicall",
    }, {
        "api": "write",
        "arguments": {
            "p0": "1",
            "p1": "h3ll0 w0rld!\n",
            "p2": "13",
        },
        "instruction_pointer": "b7768cf9",
        "pid": 681,
        "process_name": "helloworld.sh",
        "raw": "Mon Jun 19 16:58:32 2017.036988 helloworld.sh@b7768cf9[681] write(1, \"h3ll0 w0rld!\\n\", 13) = 13\n",
        "return_value": "13",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 32, 36988),
        "type": "apicall",
    }, {
        "api": "read",
        "arguments": {
            "p0": "10",
            "p1": "0x800665c0",
            "p2": "8192",
        },
        "instruction_pointer": "b7768cf9",
        "pid": 681,
        "process_name": "helloworld.sh",
        "raw": "Mon Jun 19 16:58:32 2017.037596 helloworld.sh@b7768cf9[681] read(10, 0x800665c0, 8192) = 0\n",
        "return_value": "0",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 32, 37596),
        "type": "apicall",
    }, {
        "api": "exit_group",
        "arguments": {
            "p0": "0"
        },
        "instruction_pointer": "b7768cf9",
        "pid": 681,
        "process_name": "helloworld.sh",
        "raw": "Mon Jun 19 16:58:32 2017.037898 helloworld.sh@b7768cf9[681] exit_group(0)\n",
        "return_value": "",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 32, 37898),
        "type": "apicall",
    }, {
        "api": "wait4",
        "arguments": {
            "p0": "-1",
            "p1": "0xbfd4a134",
            "p2": "0x0",
            "p3": "0x0",
        },
        "instruction_pointer": "b7769cf9",
        "pid": 680,
        "process_name": "sh",
        "raw": "Mon Jun 19 16:58:31 2017.850098 sh@b7769cf9[680] wait4(-1, 0xbfd4a134, 0x0, 0x0) = 681\n",
        "return_value": "681",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 850098),
        "type": "apicall",
    }, {
        "api": "sigreturn",
        "arguments": {},
        "instruction_pointer": "b7769cf9",
        "pid": 680,
        "process_name": "sh",
        "raw": "Mon Jun 19 16:58:32 2017.051317 sh@b7769cf9[680] sigreturn() = 681\n",
        "return_value": "681",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 32, 51317),
        "type": "apicall",
    }, {
        "api": "exit_group",
        "arguments": {
            "p0": "0"
        },
        "instruction_pointer": "b7769cf9",
        "pid": 680,
        "process_name": "sh",
        "raw": "Mon Jun 19 16:58:32 2017.051973 sh@b7769cf9[680] exit_group(0)\n",
        "return_value": "",
        "status": "",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 32, 51973),
        "type": "apicall",
    }, {
        "api": "write",
        "arguments": {
            "p0": "2",
            "p1": "BusyBox v1.16.0 (2010-02-06 04:51:36 CST)",
            "p2": "41",
        },
        "instruction_pointer": "80dbdde",
        "pid": 704,
        "process_name": "busybox-i686",
        "raw": "Tue Jun 20 15:39:30 2017.141870 busybox-i686@80dbdde[704] write(2, \"BusyBox v1.16.0 \\x282010-02-06 04:51:36 CST\\x29\", 41) = 41\n",
        "return_value": "41",
        "status": "",
        "time": datetime.datetime(2017, 6, 20, 15, 39, 30, 141870),
        "type": "apicall",
    }, {
        "api": "write",
        "arguments": {
            "p0": "2",
            "p1": "Copyright (C) 1998-2009 Erik Andersen, Rob La",
            "p2": "480",
        },
        "instruction_pointer": "80dbdde",
        "pid": 668,
        "process_name": "busybox-i686",
        "raw": "Thu Jun 22 10:22:06 2017.766807 busybox-i686@80dbdde[668] write(2, \"Copyright \\x28C\\x29 1998-2009 Erik Andersen\\x2c Rob La\", 480) = 480\n",
        "return_value": "480",
        "status": "",
        "time": datetime.datetime(2017, 6, 22, 10, 22, 6, 766807),
        "type": "apicall",
    }, {
        "api": "execve",
        "arguments": {
            "p0": "/usr/bin/sh",
            "p1": ["sh", "-c", "/tmp/comma,sh"],
            "p2": ["COMMA_IN_ARRAY=it,works", "HOME=/root"],
        },
        "instruction_pointer": "b774dcf9",
        "pid": 680,
        "process_name": "python",
        "raw": "Mon Jun 19 16:58:31 2017.445170 python@b774dcf9[680] execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"/tmp/comma\\x2csh\"], [\"COMMA_IN_ARRAY=it\\x2cworks\", \"HOME=/root\"]) = -2 (ENOENT)\n",
        "return_value": "-2",
        "status": "ENOENT",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 445170),
        "type": "apicall",
    }, {
        "api": "execve",
        "arguments": {
            "p0": "/usr/bin/sh",
            "p1": ["sh", "-c", "/tmp/bracket]sh"],
            "p2": ["LANGUAGE=en_US:en", "HOME=/root"],
        },
        "instruction_pointer": "b774dcf9",
        "pid": 680,
        "process_name": "python",
        "raw": "Mon Jun 19 16:58:31 2017.445170 python@b774dcf9[680] execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"/tmp/bracket\\x5dsh\"], [\"LANGUAGE=en_US:en\", \"HOME=/root\"]) = -2 (ENOENT)\n",
        "return_value": "-2",
        "status": "ENOENT",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 445170),
        "type": "apicall",
    }, {
        "api": "execve",
        "arguments": {
            "p0": "/usr/bin/sh",
            "p1": ["sh", "-c", u"/tmp/utf8\xc4invld"],
            "p2": ["LANGUAGE=en_US:en", "HOME=/root"],
        },
        "instruction_pointer": "b774dcf9",
        "pid": 680,
        "process_name": "python",
        "raw": "Mon Jun 19 16:58:31 2017.445170 python@b774dcf9[680] execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"/tmp/utf8\\xc4invld\"], [\"LANGUAGE=en_US:en\", \"HOME=/root\"]) = -2 (ENOENT)\n",
        "return_value": "-2",
        "status": "ENOENT",
        "time": datetime.datetime(2017, 6, 19, 16, 58, 31, 445170),
        "type": "apicall",
    }, {
        "api": "set_thread_area",
        "arguments": {
            "p0": {
                "entry_number": "4294967295",
                "base_addr": "3078293568",
                "limit": "1048575",
                "seg_32bit": "1",
                "contents": "0",
                "read_exec_only": "0",
                "limit_in_pages": "1",
                "seg_not_present": "0",
                "useable": "1",
            },
        },
        "instruction_pointer": "b77b5a21",
        "pid": 818,
        "process_name": "sh",
        "raw": "Thu Jul 27 09:51:08 2017.595142 sh@b77b5a21[818] set_thread_area({entry_number=4294967295, base_addr=3078293568, limit=1048575, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0\n",
        "return_value": "0",
        "status": "",
        "time": datetime.datetime(2017, 7, 27, 9, 51, 8, 595142),
        "type": "apicall"
    }, {
        "api": "rt_sigaction",
        "arguments": {
            "p0": "SIGCHLD",
            "p1": [
                "0x55644b6bf5a0",
                "SA_RESTORER",
                "0x7f30ca2447f0",
                [
                    "SIGHUP|SIGINT|SIGQUIT|SIGILL|SIGTRAP|SIGABRT|"
                    "SIGBUS|SIGFPE|SIGKILL|SIGUSR1|SIGSEGV|SIGPIPE|"
                    "SIGUSR2|SIGALRM|SIGTERM|SIGCHLD|SIGCONT|SIGSTOP|"
                    "SIGTSTP|SIGTTIN|SIGTTOU|SIGURG|SIGXCPU|SIGXFSZ|"
                    "SIGVTALRM|SIGPROF|SIGWINCH|SIGIO/SIGPOLL|SIGPWR|"
                    "SIGSYS]"
                ],
            ],
            "p2": "0x0",
            "p3": "8",
        },
        "instruction_pointer": "7f30ca2448ee",
        "pid": 900,
        "process_name": "sh",
        "raw": "Tue Aug  8 13:05:42 2017.464622 sh@7f30ca2448ee[900] rt_sigaction(SIGCHLD, {0x55644b6bf5a0, SA_RESTORER, 0x7f30ca2447f0, [SIGHUP|SIGINT|SIGQUIT|SIGILL|SIGTRAP|SIGABRT|SIGBUS|SIGFPE|SIGKILL|SIGUSR1|SIGSEGV|SIGPIPE|SIGUSR2|SIGALRM|SIGTERM|SIGCHLD|SIGCONT|SIGSTOP|SIGTSTP|SIGTTIN|SIGTTOU|SIGURG|SIGXCPU|SIGXFSZ|SIGVTALRM|SIGPROF|SIGWINCH|SIGIO/SIGPOLL|SIGPWR|SIGSYS]}, 0x0, 8) = 0\n",
        "return_value": "0",
        "status": "",
        "time": datetime.datetime(2017, 8, 8, 13, 5, 42, 464622),
        "type": "apicall"
    }, {
        "api": "sysinfo",
        "arguments": {
            "p0": {
                "bufferram": "3212869720",
                "freeram": "3077782043",
                "freeswap": "3",
                "loads": [
                    "0", "3077892816", "3212869720",
                ],
                "procs": "20776",
                "sharedram": "134535000",
                "totalram": "3212869792",
                "totalswap": "3077892724",
                "uptime": "-1217188199"
            },
        },
        "instruction_pointer": "b7728cf9",
        "pid": 821,
        "process_name": "bash",
        "raw": "Mon Aug 28 14:29:32 2017.619873 bash@b7728cf9[821] sysinfo({uptime=-1217188199, loads=[0, 3077892816, 3212869720], totalram=3212869792, freeram=3077782043, sharedram=134535000, bufferram=3212869720, totalswap=3077892724, freeswap=3, procs=20776}) = 0\n",
        "return_value": "0",
        "status": "",
        "time": datetime.datetime(2017, 8, 28, 14, 29, 32, 619873),
        "type": "apicall"
    }]
