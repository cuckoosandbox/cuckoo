# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import struct

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import BsonParser

log = logging.getLogger(__name__)

ERROR_SUCCESS = 0


def NT_SUCCESS(value):
    return value % 2**32 < 0x80000000

class BehaviorReconstructor(object):
    """Reconstructs the behavior of behavioral API logs."""
    def __init__(self):
        self.files = {}
        self.behavior = {}

    def report(self, category, arg=None, **kwargs):
        if category not in self.behavior:
            self.behavior[category] = []

        if arg and kwargs:
            raise Exception("Can't have both args and kwargs!")

        value = arg or kwargs
        if value and value not in self.behavior[category]:
            self.behavior[category].append(value)

    def finish(self):
        for f in self.files.values():
            self._report_file(f)

    def results(self):
        return self.behavior

    def _report_file(self, f):
        if f["read"]:
            self.report("file_read", f["filepath"])

        if f["written"]:
            self.report("file_written", f["filepath"])

    # Generic file & directory stuff.

    def _api_CreateDirectoryW(self, return_value, arguments):
        self.report("directory_created", arguments["dirpath"])

    _api_CreateDirectoryExW = _api_CreateDirectoryW

    def _api_RemoveDirectoryA(self, return_value, arguments):
        self.report("directory_removed", arguments["dirpath"])

    _api_RemoveDirectoryW = _api_RemoveDirectoryA

    def _api_MoveFileWithProgressW(self, return_value, arguments):
        self.report("file_moved",
                    src=arguments["oldfilepath"],
                    dst=arguments["newfilepath"])

    def _api_CopyFileA(self, return_value, arguments):
        self.report("file_copied",
                    src=arguments["oldfilepath"],
                    dst=arguments["newfilepath"])

    _api_CopyFileW = _api_CopyFileA
    _api_CopyFileExW = _api_CopyFileA

    def _api_DeleteFileA(self, return_value, arguments):
        self.report("file_deleted", arguments["filepath"])

    _api_DeleteFileW = _api_DeleteFileA
    _api_NtDeleteFile = _api_DeleteFileA

    def _api_FindFirstFileExA(self, return_value, arguments):
        self.report("directory_enumerated", arguments["filepath"])

    _api_FindFirstFileExW = _api_FindFirstFileExA

    # File stuff.

    def _api_NtCreateFile(self, return_value, arguments):
        if NT_SUCCESS(return_value):
            self.files[arguments["file_handle"]] = {
                "read": False,
                "written": False,
                "filepath": arguments["filepath"],
            }

        self.report("file_opened", arguments["filepath"])

    _api_NtOpenFile = _api_NtCreateFile

    def _api_NtReadFile(self, return_value, arguments):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            self.files[h]["read"] = True

    def _api_NtWriteFile(self, return_value, arguments):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            self.files[h]["written"] = True

    # Registry stuff.

    def _api_RegOpenKeyExA(self, return_value, arguments):
        self.report("regkey_opened", arguments["regkey"])

    _api_RegOpenKeyExW = _api_RegOpenKeyExA
    _api_RegCreateKeyExA = _api_RegOpenKeyExA
    _api_RegCreateKeyExW = _api_RegOpenKeyExA

    def _api_RegDeleteKeyA(self, return_value, arguments):
        self.report("regkey_deleted", arguments["regkey"])

    _api_RegDeleteKeyW = _api_RegDeleteKeyA
    _api_RegDeleteValueA = _api_RegDeleteKeyA
    _api_RegDeleteValueW = _api_RegDeleteKeyA
    _api_NtDeleteValueKey = _api_RegDeleteKeyA

    def _api_RegQueryValueExA(self, return_value, arguments):
        self.report("regkey_read", arguments["regkey"])

    _api_RegQueryValueExW = _api_RegQueryValueExA
    _api_NtQueryValueKey = _api_RegQueryValueExA

    def _api_RegSetValueExA(self, return_value, arguments):
        self.report("regkey_written", arguments["regkey"])

    _api_RegSetValueExW = _api_RegSetValueExA
    _api_NtSetValueKey = _api_RegSetValueExA

    def _api_NtClose(self, return_value, arguments):
        h = arguments["handle"]
        if h in self.files:
            self._report_file(self.files[h])
            del self.files[h]

    def _api_RegCloseKey(self, return_value, arguments):
        args = dict(handle=arguments["key_handle"])
        return self._api_NtClose(return_value, args)

    # Network stuff.

    def _api_URLDownloadToFileW(self, return_value, arguments):
        self.report("downloads_file", arguments["url"])
        self.report("file_written", arguments["filepath"])

    def _api_InternetConnectA(self, return_value, arguments):
        self.report("connects_host", arguments["hostname"])

    _api_InternetConnectW = _api_InternetConnectA

    def _api_InternetOpenUrlA(self, return_value, arguments):
        self.report("fetches_url", arguments["url"])

    _api_InternetOpenUrlW = _api_InternetOpenUrlA

    def _api_DnsQuery_A(self, return_value, arguments):
        if arguments["hostname"]:
            self.report("resolves_host", arguments["hostname"])

    _api_DnsQuery_W = _api_DnsQuery_A
    _api_DnsQuery_UTF8 = _api_DnsQuery_A
    _api_getaddrinfo = _api_DnsQuery_A
    _api_GetAddrInfoW = _api_DnsQuery_A
    _api_gethostbyname = _api_DnsQuery_A

    def _api_connect(self, return_value, arguments):
        self.report("connects_ip", arguments["ip_address"])

    # Mutex stuff
    def _api_NtCreateMutant(self, return_value, arguments):
        self.report("mutex", arguments["mutant_name"])

    _api_ConnectEx = _api_connect

class BsonHandler(object):
    """Handler for the BsonParser interface."""
    def __init__(self, path):
        self.f = open(path, "rb")
        self.proc = {}
        self.calls = {}
        self.stats = {}
        self.reconstructor = None
        self.first_seen = None
        self.hashes = []

    def finish(self):
        self.reconstructor.finish()

    def results(self):
        self.finish()

        self.proc["summary"] = self.reconstructor.results()

        return {
            "process": self.proc,
            "calls": self.calls,
            "apistats": self.stats,
        }

    def read(self, length):
        if not length:
            return ""

        buf = self.f.read(length)
        if not buf or length != len(buf):
            raise EOFError

        return buf

    def log_process(self, context, timestring, pid, ppid,
                    modulepath, procname):
        self.first_seen = int(timestring.strftime("%s"))
        self.proc = {
            "process_path": procname,
            "first_seen": self.first_seen,
            "process_identifier": pid,
            "parent_process_identifier": ppid,
            "threads": [],
        }

        self.reconstructor = BehaviorReconstructor()

    def log_anomaly(self, category, tid, funcname, msg):
        self.calls[tid].append({
            "api": "__anomaly__",
            "category": category,
            "funcname": funcname,
            "message": msg,
        })

    def log_call(self, context, apiname, category, arguments):
        _, status, return_value, tid, timediff, stacktrace, uniqhash = context

        if tid not in self.calls:
            self.calls[tid] = []

        for key, value in arguments.items():
            if isinstance(value, basestring):
                arguments[key] = unicode(value)

        self.stats[apiname] = self.stats.get(apiname, 0) + 1

        self.calls[tid].append({
            "api": apiname,
            "status": status,
            "return_value": return_value,
            "arguments": arguments,
            "time": self.first_seen + timediff / 1000.0,
        })

        if stacktrace:
            self.calls[tid][-1]["stacktrace"] = stacktrace

        fn = getattr(self.reconstructor, "_api_%s" % apiname, None)
        if fn is not None:
            fn(return_value, arguments)

        self.hashes.append(uniqhash)

class BehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    key = "behavior2"

    def __init__(self):
        self.cfg = Config()

    def _enum_logs(self):
        """Enumerate all behavior logs."""
        if not os.path.exists(self.logs_path):
            log.warning("Analysis results folder does not exist at path %r.", self.logs_path)
            return

        logs = os.listdir(self.logs_path)
        if not logs:
            log.warning("Analysis results folder does not contain any behavior log files.")
            return

        for fname in logs:
            path = os.path.join(self.logs_path, fname)
            if not os.path.isfile(path):
                log.warning("Behavior log file %r is not a file.", fname)
                continue

            if fname.endswith(".hashes"):
                continue

            if not fname.endswith(".bson"):
                log.critical("Behavioral log file %r is not in bson format, version mismatch!", fname)
                continue

            # TODO If analysis-size-limit is set to zero then ignore this check.
            if os.stat(path).st_size > self.cfg.processing.analysis_size_limit:
                log.info("Behavior log file %r is too big, skipped.", fname)
                continue

            yield path

    def _parse_log(self, path):
        """Parse a behavioral log."""
        handler = BsonHandler(path)
        parser = BsonParser(handler)

        while True:
            try:
                parser.read_next_message()
            except EOFError:
                break

        return handler.results(), handler.hashes

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        behavior = {
            "processes": [],
        }

        for path in self._enum_logs():
            proc, hashes = self._parse_log(path)
            process = proc["process"]
            process["apistats"] = proc["apistats"]

            # Write all hashes to a file.
            with open(path.replace(".bson", ".hashes"), "wb") as f:
                f.write("".join(struct.pack("q", h) for h in hashes))

            for tid, calls in proc["calls"].items():
                thread = dict(thread_identifier=tid, calls=calls)
                process["threads"].append(thread)

            behavior["processes"].append(process)

        return behavior
