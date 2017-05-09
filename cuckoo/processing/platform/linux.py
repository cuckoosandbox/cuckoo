# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime
import re

import dateutil.parser
from cuckoo.common.abstracts import BehaviorHandler

log = logging.getLogger(__name__)


class FilteredProcessLog(list):
    def __init__(self, eventstream, **kwfilters):
        self.eventstream = eventstream
        self.kwfilters = kwfilters

    def __iter__(self):
        for event in self.eventstream:
            for k, v in self.kwfilters.items():
                if event[k] != v:
                    continue

                del event["type"]
                yield event

    def __nonzero__(self):
        return True

class LinuxSystemTap(BehaviorHandler):
    """Parses systemtap/strace generated plaintext logs (see stuff/strace.stp)."""

    key = "processes"

    def __init__(self, *args, **kwargs):
        super(LinuxSystemTap, self).__init__(*args, **kwargs)

        self.processes = []
        self.pids_seen = set()
        self.forkmap = {}
        self.matched = False

        self._check_for_probelkm()

    def _check_for_probelkm(self):
        path_lkm = os.path.join(self.analysis.logs_path, "all.lkm")
        if os.path.exists(path_lkm):
            lines = open(path_lkm).readlines()

            forks = [re.findall("task (\d+)@0x[0-9a-f]+ forked to (\d+)@0x[0-9a-f]+", line) for line in lines]
            self.forkmap = dict((j, i) for i, j in reduce(lambda x, y: x+y, forks, []))

            # self.results["source"].append("probelkm")

    def handles_path(self, path):
        if path.endswith(".stap"):
            self.matched = True
            return True

    def parse(self, path):
        parser = StapParser(open(path))

        for event in parser:
            pid = event["pid"]
            if pid not in self.pids_seen:
                self.pids_seen.add(pid)
                ppid = self.forkmap.get(pid, -1)

                process = {
                    "pid": pid,
                    "ppid": ppid,
                    "process_name": event["process_name"],
                    "first_seen": event["time"],
                }

                # create a process event as we don't have those with linux+systemtap
                pevent = dict(process)
                pevent["type"] = "process"
                yield pevent

                process["calls"] = FilteredProcessLog(parser, pid=pid)
                self.processes.append(process)

            yield event

    def run(self):
        if not self.matched:
            return

        self.processes.sort(key=lambda process: process["first_seen"])
        return self.processes

class LinuxStrace(BehaviorHandler):
    """Parses systemtap/strace generated plaintext logs (see stuff/strace.stp)."""

    key = "processes"

    def __init__(self, *args, **kwargs):
        super(LinuxStrace, self).__init__(*args, **kwargs)

        self.processes = []
        self.pids_seen = set()
        self.forkmap = {}
        self.matched = False
        self._check_for_straceds()

    def _check_for_straceds(self):
        if os.path.exists(self.analysis.logs_path):
            for path in os.listdir(self.analysis.logs_path):
                if path.startswith("straced.") and path != "straced.error":
                    current_pid = path.replace("straced.", "")
                    path_straced = os.path.join(self.analysis.logs_path, path)
                    if os.path.exists(path_straced):
                        lines = open(path_straced).readlines()
                        #get pid from filename and add fork one
                        forks = [re.findall("fork\(\)\s+= (\d+)", line) for line in lines]
                        if forks:
                            #strace is multiple files not only one as systemtap
                            self.forkmap.update(dict((i, current_pid) for i in reduce(lambda x, y: x+y, forks, [])))

    def handles_path(self, path):
        path = os.path.basename(path)
        if path.startswith("straced."):
            self.matched = True
            return True

    def parse(self, path):
        parser = StraceParser(path)
        for event in parser:
            pid = event["pid"]
            if pid not in self.pids_seen:
                self.pids_seen.add(pid)
                ppid = self.forkmap.get(str(pid), -1)

                process = {
                    "pid": pid,
                    "ppid": ppid,
                    "process_name": event["process_name"],
                    "first_seen": event["time"],
                }

                # create a process event as we don't have those with linux+systemtap
                pevent = dict(process)
                pevent["type"] = "process"
                yield pevent

                process["calls"] = FilteredProcessLog(parser, pid=pid)
                self.processes.append(process)

            yield event

    def run(self):
        if not self.matched:
            return

        self.processes.sort(key=lambda process: process["first_seen"])
        return self.processes

class StraceParser(object):
    """Handle strace logs from the Linux analyzer."""
    # https://github.com/doomedraven/cuckoo/blob/6d925463067a71b16c80ef2eaf36a467fac92f61/cuckoo/common/abstracts.py
    def __init__(self, path):
        self.fd = open(path)
        self.path = path

    def __iter__(self):
        self.fd.seek(0)
        pid = os.path.basename(self.path).split(".")[1]
        for line in self.fd:
            parts = re.match("^(\w+)\((.*)\)[ ]{1,}=? ([-]?\d)", line)
            if not parts:
                #log.warning("Could not parse syscall trace line: %s", line.strip())
                continue

            fn, arguments, retval = parts.groups()
            """
            if fn in SOCKET_SYSCALL_NAMES:
                print "network", fn
            elif fn in SOCKET_SYSCALL_FILESYSTEM_NAMES:
                print "filesystem", fn
            elif fn in SOCKET_SYSCALL_PROCESS_NAMES:
                print "process", fn
            """

            argsplit = arguments.split(", ")
            tmp_argslist = list()
            for pos in range(len(argsplit)):
                if argsplit[pos].startswith("{"):
                    argsplit[pos] = argsplit[pos][1:]
                if argsplit[pos].endswith("}"):
                    argsplit[pos] = argsplit[pos][:-1]
                tmp_argslist.append(argsplit[pos])
            arguments = dict(("p%u" % pos, tmp_argslist[pos]) for pos in range(len(tmp_argslist)))
            #print {"time": datetime.datetime.now(), "process_name": "", "pid": pid, "instruction_pointer": None, "api": fn, "arguments": arguments, "return_value": retval, "status": None, "type": "apicall", "raw": line}
            yield {
                "time": datetime.datetime.now(), "process_name": "", "pid": int(pid),
                "instruction_pointer": None, "api": fn, "arguments": arguments,
                "return_value": retval, "status": None,
                "type": "apicall", "raw": line
            }

class StapParser(object):
    """Handle .stap logs from the Linux analyzer."""

    def __init__(self, fd):
        self.fd = fd

    def __iter__(self):
        self.fd.seek(0)

        for line in self.fd:
            # 'Thu May  7 14:58:43 2015.390178 python@7f798cb95240[2114] close(6) = 0\n'
            # datetime is 31 characters
            datetimepart, rest = line[:31], line[32:]

            # incredibly sophisticated date time handling
            dtms = datetime.timedelta(0, 0, int(datetimepart.split(".", 1)[1]))
            dt = dateutil.parser.parse(datetimepart.split(".", 1)[0]) + dtms

            parts = re.match("^(.+)?@([a-f0-9]+)\[(\d+)\] (\w+)\((.*)\) = (\S+){0,1}\s{0,1}(\(\w+\)){0,1}$", rest)
            if not parts:
                parts = re.match("^(.+)?@([a-f0-9]+)\[(\d+)\] (\w+)\((.*)\) =()()$", rest)

            if not parts:
                log.warning("Could not parse syscall trace line: %s", line)
                continue

            pname, ip, pid, fn, arguments, retval, ecode = parts.groups()
            argsplit = arguments.split(", ")
            arguments = dict(("p%u" % pos, argsplit[pos]) for pos in range(len(argsplit)))

            pid = int(pid) if pid.isdigit() else -1

            yield {
                "time": dt, "process_name": pname, "pid": pid,
                "instruction_pointer": ip, "api": fn, "arguments": arguments,
                "return_value": retval, "status": ecode,
                "type": "apicall", "raw": line,
            }

