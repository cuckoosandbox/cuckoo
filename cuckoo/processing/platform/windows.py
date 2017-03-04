# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import io
import logging
import re
import shlex

from cuckoo.common.abstracts import BehaviorHandler
from cuckoo.common.netlog import BsonParser
from cuckoo.common.utils import guid_name, jsbeautify, htmlprettify

log = logging.getLogger(__name__)

class MonitorProcessLog(list):
    """Yields each API call event to the parent handler. Optionally it may
    beautify certain API calls."""

    def __init__(self, eventstream, modules):
        self.eventstream = eventstream
        self.modules = modules
        self.first_seen = None
        self.has_apicalls = False

    def init(self):
        self.services = {}
        self.vbe6_ptrs = {}
        self.vbe6_func = {}

    def _api_COleScript_Compile(self, event):
        event["raw"] = "script",
        event["arguments"]["script"] = \
            jsbeautify(event["arguments"]["script"])

    def _api_CWindow_AddTimeoutCode(self, event):
        event["raw"] = "code",
        event["arguments"]["code"] = jsbeautify(event["arguments"]["code"])

    def _api_CElement_put_innerHTML(self, event):
        event["raw"] = "html",
        event["arguments"]["html"] = htmlprettify(event["arguments"]["html"])

    def _api_CDocument_write(self, event):
        event["raw"] = "lines",
        for idx, line in enumerate(event["arguments"]["lines"]):
            event["arguments"]["lines"][idx] = htmlprettify(line)

    def _api_CIFrameElement_CreateElement(self, event):
        """Lowercases the attribute keys."""
        attrs = {}
        for key, value in event["arguments"]["attributes"].items():
            attrs[key.lower()] = value

        event["arguments"]["attributes"] = attrs

    def _remember_service_name(self, event):
        """Keep track of the name of this service."""
        service_name = event["arguments"]["service_name"]
        # We've added logging of the service_handle to the API signature in
        # the Monitor, but for backwards compatibility we'll keep it as
        # follows for now.
        service_handle = "0x%08x" % event["return_value"]
        self.services[service_handle] = service_name

    _api_OpenServiceA = _remember_service_name
    _api_OpenServiceW = _remember_service_name
    _api_CreateServiceA = _remember_service_name
    _api_CreateServiceW = _remember_service_name

    def _add_service_name(self, event):
        service_name = self.services.get(event["arguments"]["service_handle"])
        event["arguments"]["service_name"] = service_name

    _api_StartServiceA = _add_service_name
    _api_StartServiceW = _add_service_name
    _api_ControlService = _add_service_name
    _api_DeleteService = _add_service_name

    # VBA Macro analysis stuff.

    def _vbe6_newobject(self, event):
        """Keep track which instance pointers belong to which classes."""
        this = event["arguments"]["this"]
        object_name = event["arguments"]["object_name"]

        self.vbe6_ptrs[this] = object_name

    _api_vbe6_CreateObject = _vbe6_newobject
    _api_vbe6_GetObject = _vbe6_newobject

    def _api_vbe6_StringConcat(self, event):
        pass

    def _api_vbe6_Import(self, event):
        # TODO Move this logic to the monitor.
        args = event["arguments"]
        if args["library"] == "VBE6.DLL" and not args["function"]:
            return False

    def _api_vbe6_GetIDFromName(self, event):
        """Keep track which function has which function index.
        This informational call is omitted from the actual logs."""
        this = event["arguments"]["this"]
        funcidx = event["arguments"]["funcidx"]
        funcname = event["arguments"]["funcname"]

        class_ = self.vbe6_ptrs.get(this, this)
        self.vbe6_func[class_, funcidx] = funcname
        return False

    def _api_vbe6_CallByName(self, event):
        """Only used by the monitor for administrative uses."""
        return False

    def _api_vbe6_Invoke(self, event):
        this = event["arguments"]["this"]
        funcidx = event["arguments"]["funcidx"]

        if this in self.vbe6_ptrs:
            event["flags"]["this"] = self.vbe6_ptrs[this]

        class_ = self.vbe6_ptrs.get(this, this)
        if class_ and (class_, funcidx) in self.vbe6_func:
            event["arguments"]["funcname"] = self.vbe6_func[class_, funcidx]

        del event["arguments"]["funcidx"]

    # PDF document analysis.

    def _api_pdf_eval(self, event):
        event["raw"] = "script",
        event["arguments"]["script"] = \
            jsbeautify(event["arguments"]["script"])

    def _api_pdf_unescape(self, event):
        event["raw"] = "string", "unescaped"

        # "%u1234" => "\x34\x12"
        # Strictly speaking this does not reflect what unescape() does, but
        # in the end it's usually just about the in-memory representation.
        event["arguments"]["unescaped"] = re.sub(
            "%u([0-9a-fA-F]{4})",
            lambda x: x.group(1).decode("hex").decode("latin-1")[::-1],
            event["arguments"]["string"]
        )

        # "%41" => "A"
        event["arguments"]["unescaped"] = re.sub(
            "%([0-9a-fA-F]{2})",
            lambda x: x.group(1).decode("hex").decode("latin-1"),
            event["arguments"]["unescaped"]
        )

    def _api___exception__(self, event):
        addr = int(event["arguments"]["exception"]["address"], 16)
        for module in self.modules:
            if "imgsize" not in module:
                continue

            baseaddr = int(module["baseaddr"], 16)
            if addr >= baseaddr and addr < baseaddr + module["imgsize"]:
                event["arguments"]["exception"]["module"] = module["basename"]
                event["arguments"]["exception"]["offset"] = addr - baseaddr

    def _api_modifier(self, event):
        """Adds flags field to CLSID and IID instances."""
        clsid = guid_name(event["arguments"].get("clsid"))
        if clsid:
            event["flags"]["clsid"] = clsid

        iid = event["arguments"].get("iid")
        if isinstance(iid, (tuple, list)):
            event["flags"]["iid"] = [guid_name(x) for x in iid]
        elif guid_name(iid):
            event["flags"]["iid"] = guid_name(iid)

    def __iter__(self):
        self.init()
        for event in self.eventstream:
            if event["type"] == "process":
                self.first_seen = event["first_seen"]
            elif event["type"] == "apicall":
                event["time"] = self.first_seen + datetime.timedelta(0, 0, event["time"] * 1000)

                # Remove the event type for reporting output.
                del event["type"]

                # Get rid of the pid (we're below the pid in the structure).
                del event["pid"]

                # Get rid of the unique hash, this is only relevant
                # for automation.
                del event["uniqhash"]

                # If available, call a modifier function.
                apiname = "_api_%s" % event["api"]
                r = getattr(self, apiname, lambda _: None)(event)

                # Generic modifier for various functions.
                self._api_modifier(event)

                # Prevent this event from being passed along by returning
                # False in a _api_() method.
                if r is not False:
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
        self.behavior = {}
        self.reboot = {}
        self.matched = False

    def handles_path(self, path):
        if path.endswith(".bson"):
            self.matched = True
            return True

    def parse(self, path):
        # Invoke parsing of current log file.
        parser = BsonParser(open(path, "rb"))
        parser.init()

        for event in parser:
            if event["type"] == "process":
                process = dict(event)
                process["calls"] = MonitorProcessLog(
                    parser, process["modules"]
                )
                self.processes.append(process)

                self.behavior[process["pid"]] = BehaviorReconstructor()
                self.reboot[process["pid"]] = RebootReconstructor()

            # Create generic events out of the windows calls.
            elif event["type"] == "apicall":
                behavior = self.behavior[event["pid"]]
                reboot = self.reboot[event["pid"]]

                for category, arg in behavior.process_apicall(event):
                    yield {
                        "type": "generic",
                        "pid": event["pid"],
                        "category": category,
                        "value": arg,
                    }

                # Process the reboot reconstructor.
                for category, args in reboot.process_apicall(event):
                    # TODO Improve this where we have to calculate the "real"
                    # time again even though we already do this in
                    # MonitorProcessLog.
                    ts = process["first_seen"] + \
                        datetime.timedelta(0, 0, event["time"] * 1000)

                    yield {
                        "type": "reboot",
                        "category": category,
                        "args": args,
                        "time": int(ts.strftime("%d")),
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

def single(key, value):
    return [(key, value)]

def multiple(*l):
    return l

class BehaviorReconstructor(object):
    """Reconstructs the behavior of behavioral API logs."""
    def __init__(self):
        self.files = {}

    def process_apicall(self, event):
        fn = getattr(self, "_api_%s" % event["api"], None)
        if fn is not None:
            ret = fn(
                event["return_value"], event["arguments"], event.get("flags")
            )
            return ret or []
        return []

    # Generic file & directory stuff.

    def _api_CreateDirectoryW(self, return_value, arguments, flags):
        return single("directory_created", arguments["dirpath"])

    _api_CreateDirectoryExW = _api_CreateDirectoryW

    def _api_RemoveDirectoryA(self, return_value, arguments, flags):
        return single("directory_removed", arguments["dirpath"])

    _api_RemoveDirectoryW = _api_RemoveDirectoryA

    def _api_MoveFileWithProgressW(self, return_value, arguments, flags):
        return single("file_moved", (
            arguments["oldfilepath"], arguments["newfilepath"]
        ))

    def _api_CopyFileA(self, return_value, arguments, flags):
        return single("file_copied", (
            arguments["oldfilepath"], arguments["newfilepath"]
        ))

    _api_CopyFileW = _api_CopyFileA
    _api_CopyFileExW = _api_CopyFileA

    def _api_DeleteFileA(self, return_value, arguments, flags):
        return single("file_deleted", arguments["filepath"])

    _api_DeleteFileW = _api_DeleteFileA
    _api_NtDeleteFile = _api_DeleteFileA

    def _api_FindFirstFileExA(self, return_value, arguments, flags):
        return single("directory_enumerated", arguments["filepath"])

    _api_FindFirstFileExW = _api_FindFirstFileExA

    def _api_LdrLoadDll(self, return_value, arguments, flags):
        return single("dll_loaded", arguments["module_name"])

    def _api_NtCreateFile(self, return_value, arguments, flags):
        self.files[arguments["file_handle"]] = arguments["filepath"]
        if NT_SUCCESS(return_value):
            status_info = flags.get("status_info", "").lower()
            if status_info in ("file_overwritten", "file_superseded"):
                return single("file_recreated", arguments["filepath"])
            elif status_info == "file_exists":
                return single("file_opened", arguments["filepath"])
            elif status_info == "file_does_not_exist":
                return single("file_failed", arguments["filepath"])
            elif status_info == "file_created":
                return single("file_created", arguments["filepath"])
            else:
                return single("file_opened", arguments["filepath"])
        else:
            return single("file_failed", arguments["filepath"])

    _api_NtOpenFile = _api_NtCreateFile

    def _api_NtReadFile(self, return_value, arguments, flags):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            return single("file_read", self.files[h])

    def _api_NtWriteFile(self, return_value, arguments, flags):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            return single("file_written", self.files[h])

    def _api_GetFileAttributesW(self, return_value, arguments, flags):
        return single("file_exists", arguments["filepath"])

    _api_GetFileAttributesExW = _api_GetFileAttributesW

    # Registry stuff.

    def _api_RegOpenKeyExA(self, return_value, arguments, flags):
        return single("regkey_opened", arguments["regkey"])

    _api_RegOpenKeyExW = _api_RegOpenKeyExA
    _api_RegCreateKeyExA = _api_RegOpenKeyExA
    _api_RegCreateKeyExW = _api_RegOpenKeyExA

    def _api_RegDeleteKeyA(self, return_value, arguments, flags):
        return single("regkey_deleted", arguments["regkey"])

    _api_RegDeleteKeyW = _api_RegDeleteKeyA
    _api_RegDeleteValueA = _api_RegDeleteKeyA
    _api_RegDeleteValueW = _api_RegDeleteKeyA
    _api_NtDeleteValueKey = _api_RegDeleteKeyA

    def _api_RegQueryValueExA(self, return_value, arguments, flags):
        return single("regkey_read", arguments["regkey"])

    _api_RegQueryValueExW = _api_RegQueryValueExA
    _api_NtQueryValueKey = _api_RegQueryValueExA

    def _api_RegSetValueExA(self, return_value, arguments, flags):
        return single("regkey_written", arguments["regkey"])

    _api_RegSetValueExW = _api_RegSetValueExA
    _api_NtSetValueKey = _api_RegSetValueExA

    def _api_NtClose(self, return_value, arguments, flags):
        self.files.pop(arguments["handle"], None)

    # Network stuff.

    def _api_URLDownloadToFileW(self, return_value, arguments, flags):
        return multiple(
            ("downloads_file", arguments["url"]),
            ("file_opened", arguments["filepath"]),
            ("file_written", arguments["filepath"]),
        )

    def _api_InternetConnectA(self, return_value, arguments, flags):
        return single("connects_host", arguments["hostname"])

    _api_InternetConnectW = _api_InternetConnectA

    def _api_InternetOpenUrlA(self, return_value, arguments, flags):
        return single("fetches_url", arguments["url"])

    _api_InternetOpenUrlW = _api_InternetOpenUrlA

    def _api_DnsQuery_A(self, return_value, arguments, flags):
        if arguments["hostname"]:
            return single("resolves_host", arguments["hostname"])

    _api_DnsQuery_W = _api_DnsQuery_A
    _api_DnsQuery_UTF8 = _api_DnsQuery_A
    _api_getaddrinfo = _api_DnsQuery_A
    _api_GetAddrInfoW = _api_DnsQuery_A
    _api_gethostbyname = _api_DnsQuery_A

    def _api_connect(self, return_value, arguments, flags):
        return single("connects_ip", arguments["ip_address"])

    # Mutex stuff

    def _api_NtCreateMutant(self, return_value, arguments, flags):
        if arguments["mutant_name"]:
            return single("mutex", arguments["mutant_name"])

    _api_ConnectEx = _api_connect

    # Process stuff.

    def _api_CreateProcessInternalW(self, return_value, arguments, flags):
        if arguments.get("track", True):
            cmdline = arguments["command_line"] or arguments["filepath"]
            return single("command_line", cmdline)

    def _api_ShellExecuteExW(self, return_value, arguments, flags):
        if arguments["parameters"]:
            cmdline = "%s %s" % (arguments["filepath"], arguments["parameters"])
        else:
            cmdline = arguments["filepath"]
        return single("command_line", cmdline)

    def _api_system(self, return_value, arguments, flags):
        return single("command_line", arguments["command"])

    # WMI stuff.

    def _api_IWbemServices_ExecQuery(self, return_value, arguments, flags):
        return single("wmi_query", arguments["query"])

    def _api_IWbemServices_ExecQueryAsync(self, return_value, arguments, flags):
        return single("wmi_query", arguments["query"])

    # GUIDs.

    def _api_CoCreateInstance(self, return_value, arguments, flags):
        return multiple(
            ("guid", arguments["clsid"]),
            ("guid", arguments["iid"]),
        )

    def _api_CoCreateInstanceEx(self, return_value, arguments, flags):
        ret = [
            ("guid", arguments["clsid"]),
        ]
        for iid in arguments["iid"]:
            ret.append(("guid", iid))
        return multiple(*ret)

    def _api_CoGetClassObject(self, return_value, arguments, flags):
        return multiple(
            ("guid", arguments["clsid"]),
            ("guid", arguments["iid"]),
        )

    # SSLv3 & TLS Master Secrets.

    def _api_Ssl3GenerateKeyMaterial(self, return_value, arguments, flags):
        if arguments["client_random"] and arguments["server_random"]:
            return single("tls_master", (
                arguments["client_random"],
                arguments["server_random"],
                arguments["master_secret"],
            ))

    def _api_PRF(self, return_value, arguments, flags):
        if arguments["type"] == "key expansion":
            return single("tls_master", (
                arguments["client_random"],
                arguments["server_random"],
                arguments["master_secret"],
            ))

class RebootReconstructor(object):
    """Reconstructs the behavior as would be seen after a reboot."""

    def process_apicall(self, event):
        fn = getattr(self, "_api_%s" % event["api"], None)
        if fn is not None:
            ret = fn(
                event["return_value"], event["arguments"], event.get("flags")
            )
            return ret or []
        return []

    def _api_delete_regkey(self, return_value, arguments, flags):
        return single("regkey_deleted", arguments["regkey"])

    _api_RegDeleteKeyA = _api_delete_regkey
    _api_RegDeleteKeyW = _api_delete_regkey
    _api_RegDeleteValueA = _api_delete_regkey
    _api_RegDeleteValueW = _api_delete_regkey
    _api_NtDeleteValueKey = _api_delete_regkey

    def parse_cmdline(self, command_line):
        """Extract the filepath and arguments from the full commandline."""
        components = shlex.split(
            io.StringIO(unicode(command_line)), posix=False
        )
        return components[0].strip('"'), components[1:]

    def _handle_run(self, arguments, flags):
        """Handle Run registry keys."""
        reg_type = flags.get("reg_type", arguments["reg_type"])
        filepath, args = self.parse_cmdline(arguments["value"])
        return multiple(
            ("regkey_written", (
                arguments["regkey"], reg_type, arguments["value"]
            )),
            ("create_process", (
                filepath, args, "explorer.exe"
            )),
        )

    def _handle_runonce(self, arguments, flags):
        """For RunOnce there is no registry key persistence."""
        filepath, args = self.parse_cmdline(arguments["value"])
        return single("create_process", (
            filepath, args, "explorer.exe",
        ))

    # TODO In an optimal world we would move this logic to a Signature, but
    # unfortunately the reboot information is already written away during the
    # Processing stage and thus the Signature stage is too late in the chain.
    _reg_regexes = [
        (_handle_run, ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"),
        (_handle_runonce, ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce"),
    ]

    def _api_set_regkey(self, return_value, arguments, flags):
        # Is this a registry key that directly affects reboot persistence?
        for fn, regex in self._reg_regexes:
            if re.match(regex, arguments["regkey"], re.I):
                return fn(self, arguments, flags)

        reg_type = flags.get("reg_type", arguments["reg_type"])
        return single("regkey_written", (
            arguments["regkey"], reg_type, arguments["value"]
        ))

    _api_RegSetValueExA = _api_set_regkey
    _api_RegSetValueExW = _api_set_regkey
    _api_NtSetValueKey = _api_set_regkey
