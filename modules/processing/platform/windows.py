# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import datetime

from lib.cuckoo.common.abstracts import BehaviorHandler
from lib.cuckoo.common.netlog import BsonParser

log = logging.getLogger(__name__)

class MonitorProcessLog(list):
    def __init__(self, eventstream):
        self.eventstream = eventstream
        self.first_seen = None
        self.has_apicalls = False

    def __iter__(self):
        # call_id = 0
        for event in self.eventstream:
            if event["type"] == "process":
                self.first_seen = event["first_seen"]
            elif event["type"] == "apicall":
                event["time"] = self.first_seen + datetime.timedelta(0, 0, event["time"] * 1000)

                # backwards compat with previous reports, remove if not necessary
                # event["repeated"] = 0
                # event["timestamp"] = logtime(event.pop("time"))
                # event["arguments"] = [dict(name=i, value=j) for i,j in event["arguments"].iteritems()]
                # event["return"] = convert_to_printable(cleanup_value(event.pop("return_value")))

                # event["is_success"] = bool(int(event.pop("status")))
                # event["id"] = call_id
                # call_id += 1

                # Remove the event type for reporting output.
                del event["type"]

                # Get rid of the pid (we're below the pid in the structure).
                del event["pid"]

                # Get rid of the unique hash, this is only relevant
                # for automation.
                del event["uniqhash"]

                yield event

    def __nonzero__(self):
        """Required for the JSON reporting module as otherwise the on-demand
        generated list of API calls would be seen as empty.

        Note that the result structure is kept between processing and
        reporting time which means that at reporting time, where this
        functionality is actually needed, the has_apicalls will already have
        been set while iterating through the BSON logs iterator in the parse()
        function of the WindowsMonitor class. We use this knowledge to pass
        along whether or not this log actually has API call events and thus
        whether it's "nonzero" or not. (The correctness of this field is
        required as otherwise the json.dump() function will fail - probably
        due to buffering issues).
        """
        return self.has_apicalls

class WindowsMonitor(BehaviorHandler):
    """Parses monitor generated logs."""
    key = "processes"

    def __init__(self, *args, **kwargs):
        super(WindowsMonitor, self).__init__(*args, **kwargs)
        self.processes = []
        self.reconstructors = {}
        self.matched = False

    def handles_path(self, path):
        if path.endswith(".bson"):
            self.matched = True
            return True

    def parse(self, path):
        # Invoke parsing of current log file.
        parser = BsonParser(open(path, "rb"))

        for event in parser:
            if event["type"] == "process":
                process = dict(event)
                process["calls"] = MonitorProcessLog(parser)
                self.processes.append(process)

                self.reconstructors[process["pid"]] = BehaviorReconstructor()

            # Create generic events out of the windows calls.
            elif event["type"] == "apicall":
                reconstructor = self.reconstructors[event["pid"]]
                res = reconstructor.process_apicall(event)

                if res and isinstance(res, tuple):
                    res = [res]

                if res:
                    for category, arg in res:
                        yield {
                            "type": "generic",
                            "pid": event["pid"],
                            "category": category,
                            "value": arg,
                        }

                # Indicate that the process has API calls. For more
                # information on this matter, see also the __nonzero__ above.
                process["calls"].has_apicalls = True

            yield event

    def run(self):
        if not self.matched:
            return

        self.processes.sort(key=lambda process: process["first_seen"])
        return self.processes

def NT_SUCCESS(value):
    return value % 2**32 < 0x80000000

class BehaviorReconstructor(object):
    """Reconstructs the behavior of behavioral API logs."""
    def __init__(self):
        self.files = {}

    def process_apicall(self, event):
        fn = getattr(self, "_api_%s" % event["api"], None)
        if fn is not None:
            return fn(event["return_value"], event["arguments"])

    # Generic file & directory stuff.

    def _api_CreateDirectoryW(self, return_value, arguments):
        return ("directory_created", arguments["dirpath"])

    _api_CreateDirectoryExW = _api_CreateDirectoryW

    def _api_RemoveDirectoryA(self, return_value, arguments):
        return ("directory_removed", arguments["dirpath"])

    _api_RemoveDirectoryW = _api_RemoveDirectoryA

    def _api_MoveFileWithProgressW(self, return_value, arguments):
        return ("file_moved", (arguments["oldfilepath"],
                               arguments["newfilepath"]))

    def _api_CopyFileA(self, return_value, arguments):
        return ("file_copied", (arguments["oldfilepath"],
                                arguments["newfilepath"]))

    _api_CopyFileW = _api_CopyFileA
    _api_CopyFileExW = _api_CopyFileA

    def _api_DeleteFileA(self, return_value, arguments):
        return ("file_deleted", arguments["filepath"])

    _api_DeleteFileW = _api_DeleteFileA
    _api_NtDeleteFile = _api_DeleteFileA

    def _api_FindFirstFileExA(self, return_value, arguments):
        return ("directory_enumerated", arguments["filepath"])

    _api_FindFirstFileExW = _api_FindFirstFileExA

    # File stuff.

    def _api_NtCreateFile(self, return_value, arguments):
        if NT_SUCCESS(return_value):
            self.files[arguments["file_handle"]] = arguments["filepath"]
            return ("file_opened", arguments["filepath"])

    _api_NtOpenFile = _api_NtCreateFile

    def _api_NtReadFile(self, return_value, arguments):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            return ("file_read", self.files[h])

    def _api_NtWriteFile(self, return_value, arguments):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            return ("file_written", self.files[h])

    # Registry stuff.

    def _api_RegOpenKeyExA(self, return_value, arguments):
        return ("regkey_opened", arguments["regkey"])

    _api_RegOpenKeyExW = _api_RegOpenKeyExA
    _api_RegCreateKeyExA = _api_RegOpenKeyExA
    _api_RegCreateKeyExW = _api_RegOpenKeyExA

    def _api_RegDeleteKeyA(self, return_value, arguments):
        return ("regkey_deleted", arguments["regkey"])

    _api_RegDeleteKeyW = _api_RegDeleteKeyA
    _api_RegDeleteValueA = _api_RegDeleteKeyA
    _api_RegDeleteValueW = _api_RegDeleteKeyA
    _api_NtDeleteValueKey = _api_RegDeleteKeyA

    def _api_RegQueryValueExA(self, return_value, arguments):
        return ("regkey_read", arguments["regkey"])

    _api_RegQueryValueExW = _api_RegQueryValueExA
    _api_NtQueryValueKey = _api_RegQueryValueExA

    def _api_RegSetValueExA(self, return_value, arguments):
        return ("regkey_written", arguments["regkey"])

    _api_RegSetValueExW = _api_RegSetValueExA
    _api_NtSetValueKey = _api_RegSetValueExA

    def _api_NtClose(self, return_value, arguments):
        self.files.pop(arguments["handle"], None)

    # Network stuff.

    def _api_URLDownloadToFileW(self, return_value, arguments):
        return [
            ("downloads_file", arguments["url"]),
            ("file_opened", arguments["filepath"]),
            ("file_written", arguments["filepath"]),
        ]

    def _api_InternetConnectA(self, return_value, arguments):
        return ("connects_host", arguments["hostname"])

    _api_InternetConnectW = _api_InternetConnectA

    def _api_InternetOpenUrlA(self, return_value, arguments):
        return ("fetches_url", arguments["url"])

    _api_InternetOpenUrlW = _api_InternetOpenUrlA

    def _api_DnsQuery_A(self, return_value, arguments):
        if arguments["hostname"]:
            return ("resolves_host", arguments["hostname"])

    _api_DnsQuery_W = _api_DnsQuery_A
    _api_DnsQuery_UTF8 = _api_DnsQuery_A
    _api_getaddrinfo = _api_DnsQuery_A
    _api_GetAddrInfoW = _api_DnsQuery_A
    _api_gethostbyname = _api_DnsQuery_A

    def _api_connect(self, return_value, arguments):
        return ("connects_ip", arguments["ip_address"])

    # Mutex stuff

    def _api_NtCreateMutant(self, return_value, arguments):
        return ("mutex", arguments["mutant_name"])

    _api_ConnectEx = _api_connect
