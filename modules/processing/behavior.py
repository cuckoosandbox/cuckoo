# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import NetlogParser, BsonParser
from lib.cuckoo.common.utils import convert_to_printable, logtime
from lib.cuckoo.common.utils import cleanup_value

log = logging.getLogger(__name__)

def fix_key(key):
    """Fix a registry key to have it normalized.
    @param key: raw key
    @returns: normalized key
    """
    res = key
    if key.lower().startswith("registry\\machine\\"):
        res = "HKEY_LOCAL_MACHINE\\" + key[17:]
    elif key.lower().startswith("registry\\user\\"):
        res = "HKEY_USERS\\" + key[14:]
    elif key.lower().startswith("\\registry\\machine\\"):
        res = "HKEY_LOCAL_MACHINE\\" + key[18:]
    elif key.lower().startswith("\\registry\\user\\"):
        res = "HKEY_USERS\\" + key[15:]

    if not res.endswith("\\\\"):
        res = res + "\\"
    return res

class ParseProcessLog(list):
    """Parses process log file."""

    def __init__(self, log_path):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.fd = None
        self.parser = None

        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.first_seen = None
        self.calls = self
        self.lastcall = None

        if os.path.exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

    def parse_first_and_reset(self):
        self.fd = open(self._log_path, "rb")

        if self._log_path.endswith(".bson"):
            self.parser = BsonParser(self)
        elif self._log_path.endswith(".raw"):
            self.parser = NetlogParser(self)
        else:
            self.fd.close()
            self.fd = None
            return

        # get the process information from file to determine
        # process id (file names)
        while not self.process_id:
            self.parser.read_next_message()

        self.fd.seek(0)

    def read(self, length):
        if not length:
            return ''
        buf = self.fd.read(length)
        if not buf or len(buf) != length:
            raise EOFError()
        return buf

    def __iter__(self):
        #import inspect
        #log.debug('iter called by this guy: {0}'.format(inspect.stack()[1]))
        return self

    def __repr__(self):
        return "<ParseProcessLog log-path: %r>" % self._log_path

    def __nonzero__(self):
        return self.wait_for_lastcall()

    def reset(self):
        self.fd.seek(0)
        self.lastcall = None

    def compare_calls(self, a, b):
        """Compare two calls for equality. Same implementation as before netlog.
        @param a: call a
        @param b: call b
        @return: True if a == b else False
        """
        if a["api"] == b["api"] and \
                a["status"] == b["status"] and \
                a["arguments"] == b["arguments"] and \
                a["return"] == b["return"]:
            return True
        return False

    def wait_for_lastcall(self):
        while not self.lastcall:
            r = None
            try:
                r = self.parser.read_next_message()
            except EOFError:
                return False

            if not r:
                return False
        return True

    def next(self):
        if not self.fd:
            raise StopIteration()

        if not self.wait_for_lastcall():
            self.reset()
            raise StopIteration()

        nextcall, self.lastcall = self.lastcall, None

        self.wait_for_lastcall()
        while self.lastcall and self.compare_calls(nextcall, self.lastcall):
            nextcall["repeated"] += 1
            self.lastcall = None
            self.wait_for_lastcall()

        return nextcall

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        self.process_id, self.parent_id, self.process_name = pid, ppid, procname
        self.first_seen = timestring

    def log_thread(self, context, pid):
        pass

    def log_call(self, context, apiname, category, arguments):
        apiindex, status, returnval, tid, timediff = context

        current_time = self.first_seen + datetime.timedelta(0, 0, timediff*1000)
        timestring = logtime(current_time)

        self.lastcall = self._parse([timestring,
                                     tid,
                                     category,
                                     apiname, 
                                     status,
                                     returnval] + arguments)

    def log_error(self, emsg):
        log.warning("ParseProcessLog error condition on log %s: %s", str(self._log_path), emsg)

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        call = {}
        arguments = []

        try:
            timestamp = row[0]    # Timestamp of current API call invocation.
            thread_id = row[1]    # Thread ID.
            category = row[2]     # Win32 function category.
            api_name = row[3]     # Name of the Windows API.
            status_value = row[4] # Success or Failure?
            return_value = row[5] # Value returned by the function.
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(6, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:
                arg_name, arg_value = row[index]
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", row[index], e)
                continue

            argument["name"] = arg_name

            argument["value"] = convert_to_printable(cleanup_value(arg_value))
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["thread_id"] = str(thread_id)
        call["category"] = category
        call["api"] = api_name
        call["status"] = bool(int(status_value))

        if isinstance(return_value, int):
            call["return"] = "0x%.08x" % return_value
        else:
            call["return"] = convert_to_printable(cleanup_value(return_value))

        call["arguments"] = arguments
        call["repeated"] = 0

        return call

class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path):
        """@param  logs_path: logs path."""
        self._logs_path = logs_path
        self.cfg = Config()

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not os.path.exists(self._logs_path):
            log.error("Analysis results folder does not exist at path \"%s\".",
                      self._logs_path)
            return results

        if len(os.listdir(self._logs_path)) == 0:
            log.error("Analysis results folder does not contain any file.")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if os.path.isdir(file_path):
                continue

            # Skipping the current log file if it's too big.
            if os.stat(file_path).st_size > self.cfg.processing.analysis_size_limit:
                log.warning("Behavioral log {0} too big to be processed, skipped.".format(file_name))
                continue

            # Invoke parsing of current log file.
            current_log = ParseProcessLog(file_path)
            if current_log.process_id is None:
                continue

            # If the current log actually contains any data, add its data to
            # the results list.
            results.append({
                "process_id": current_log.process_id,
                "process_name": current_log.process_name,
                "parent_id": current_log.parent_id,
                "first_seen": logtime(current_log.first_seen),
                "calls": current_log.calls,
            })

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

class Summary:
    """Generates summary information."""

    key = "summary"

    def __init__(self):
        self.keys = []
        self.mutexes = []
        self.files = []
        self.handles = []

    def _check_registry(self, registry, subkey, handle):
        for known_handle in self.handles:
            if handle != 0 and handle == known_handle["handle"]:
                return None

        name = ""

        if registry == 0x80000000:
            name = "HKEY_CLASSES_ROOT\\"
        elif registry == 0x80000001:
            name = "HKEY_CURRENT_USER\\"
        elif registry == 0x80000002:
            name = "HKEY_LOCAL_MACHINE\\"
        elif registry == 0x80000003:
            name = "HKEY_USERS\\"
        elif registry == 0x80000004:
            name = "HKEY_PERFORMANCE_DATA\\"
        elif registry == 0x80000005:
            name = "HKEY_CURRENT_CONFIG\\"
        elif registry == 0x80000006:
            name = "HKEY_DYN_DATA\\"
        else:
            for known_handle in self.handles:
                if registry == known_handle["handle"]:
                    name = known_handle["name"] + "\\"

        key = fix_key(name + subkey)
        self.handles.append({"handle": handle, "name": key})
        return key

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """

        if call["api"].startswith("RegOpenKeyEx") or call["api"].startswith("RegCreateKeyEx"):
            registry = 0
            subkey = ""
            handle = 0

            for argument in call["arguments"]:
                if argument["name"] == "Registry":
                    registry = int(argument["value"], 16)
                elif argument["name"] == "SubKey":
                    subkey = argument["value"]
                elif argument["name"] == "Handle":
                    handle = int(argument["value"], 16)

            name = self._check_registry(registry, subkey, handle)
            if name and name not in self.keys:
                self.keys.append(name)
        elif call["api"].startswith("NtOpenKey"):
            registry = -1
            subkey = ""
            handle = 0

            for argument in call["arguments"]:
                if argument["name"] == "ObjectAttributes":
                    subkey = argument["value"]
                elif argument["name"] == "KeyHandle":
                    handle = int(argument["value"], 16)

            name = self._check_registry(registry, subkey, handle)
            if name and name not in self.keys:
                self.keys.append(name)
        elif call["api"].startswith("NtDeleteValueKey"):
            registry = -1
            subkey = ""
            handle = 0

            for argument in call["arguments"]:
                if argument["name"] == "ValueName":
                    subkey = argument["value"]
                elif argument["name"] == "KeyHandle":
                    handle = int(argument["value"], 16)

            name = self._check_registry(registry, subkey, handle)
            if name and name not in self.keys:
                self.keys.append(name)
        elif call["api"].startswith("RegCloseKey"):
            handle = 0

            for argument in call["arguments"]:
                if argument["name"] == "Handle":
                    handle = int(argument["value"], 16)

            if handle != 0:
                for a in self.handles:
                    if a["handle"] == handle:
                        try:
                            self.handles.remove(a)
                        except ValueError:
                            pass

        elif call["category"] == "filesystem":
            for argument in call["arguments"]:
                if argument["name"] == "FileName":
                    value = argument["value"].strip()
                    if not value:
                        continue

                    if value not in self.files:
                        self.files.append(value)

        elif call["category"] == "synchronization":
            for argument in call["arguments"]:
                if argument["name"] == "MutexName":
                    value = argument["value"].strip()
                    if not value:
                        continue

                    if value not in self.mutexes:
                        self.mutexes.append(value)

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, mutexes and files.
        """
        return {"files": self.files, "keys": self.keys, "mutexes": self.mutexes}

class Enhanced(object):
    """Generates a more extensive high-level representation than Summary."""

    key = "enhanced"

    def __init__(self, details=False):
        """
        @param details: Also add some (not so relevant) Details to the log
        """
        self.currentdir = "C: "
        self.eid = 0
        self.details = details
        self.filehandles = {}
        self.servicehandles = {}
        self.keyhandles = {
            "0x80000000": "HKEY_CLASSES_ROOT\\",
            "0x80000001": "HKEY_CURRENT_USER\\",
            "0x80000002": "HKEY_LOCAL_MACHINE\\",
            "0x80000003": "HKEY_USERS\\",
            "0x80000004": "HKEY_PERFORMANCE_DATA\\",
            "0x80000005": "HKEY_CURRENT_CONFIG\\",
            "0x80000006": "HKEY_DYN_DATA\\"
        }
        self.modules = {}
        self.procedures = {}
        self.events = []

    def _add_procedure(self, mbase, name, base):
        """
        Add a procedure address
        """
        self.procedures[base] = "{0}:{1}".format(self._get_loaded_module(mbase), name)

    def _add_loaded_module(self, name, base):
        """
        Add a loaded module to the internal database
        """
        self.modules[base] = name

    def _get_loaded_module(self, base):
        """
        Get the name of a loaded module from the internal db
        """
        return self.modules.get(base, "")

    # Registry
    def _add_keyhandle(self, registry, subkey, handle):
        """
        @registry: returned, new handle
        @handle: handle to base key
        @subkey: subkey to add
        """
        if handle != 0 and handle in self.keyhandles:
            return self.keyhandles[handle]

        name = ""
        if registry and registry != "0x00000000" and \
                registry in self.keyhandles:
            name = self.keyhandles[registry]

        nkey = name + subkey
        nkey = fix_key(nkey)

        self.keyhandles[handle] = nkey

        return nkey

    def _remove_keyhandle(self, handle):
        key = self._get_keyhandle(handle)

        if handle in self.keyhandles:
            self.keyhandles.pop(handle)

        return key

    def _get_keyhandle(self, handle):
        return self.keyhandles.get(handle, "")

    def _process_call(self, call):
        """ Gets files calls
        @return: information list
        """
        def _load_args(call):
            """
            Load arguments from call
            """
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res

        def _generic_handle_details(self, call, item):
            """
            Generic handling of api calls
            @call: the call dict
            @item: Generic item to process
            """
            event = None
            if call["api"] in item["apis"]:
                args = _load_args(call)
                self.eid += 1

                event = {
                    "event": item["event"],
                    "object": item["object"],
                    "timestamp": call["timestamp"],
                    "eid": self.eid,
                    "data": {}
                }

                for logname, dataname in item["args"]:
                    event["data"][logname] = args.get(dataname)
                return event

        def _generic_handle(self, data, call):
            """Generic handling of api calls."""
            for item in data:
                event = _generic_handle_details(self, call, item)
                if event:
                    return event

            return None

        # Generic handles
        def _add_handle(handles, handle, filename):
            handles[handle] = filename

        def _remove_handle(handles, handle):
            if handle in handles:
                handles.pop(handle)

        def _get_handle(handles, handle):
            return handles.get(handle)

        def _get_service_action(control_code):
            """@see: http://msdn.microsoft.com/en-us/library/windows/desktop/ms682108%28v=vs.85%29.aspx"""
            codes = {1: "stop",
                     2: "pause",
                     3: "continue",
                     4: "info"}

            default = "user" if control_code >= 128 else "notify"
            return codes.get(control_code, default)

        event = None

        gendat = [
            {
                "event": "move",
                "object": "file",
                "apis": [
                    "MoveFileWithProgressW",
                    "MoveFileExA",
                    "MoveFileExW"
                ],
                "args": [
                    ("from", "ExistingFileName"),
                    ("to", "NewFileName")
                ]
            },
            {
                "event": "copy",
                "object": "file",
                "apis": [
                    "CopyFileA",
                    "CopyFileW",
                    "CopyFileExW",
                    "CopyFileExA"
                ],
                "args": [
                    ("from", "ExistingFileName"),
                    ("to", "NewFileName")
                ]
            },
            {
                "event": "delete",
                "object": "file",
                "apis": [
                    "DeleteFileA",
                    "DeleteFileW",
                    "NtDeleteFile"
                ],
                "args": [("file", "FileName")]
            },
            {
                "event": "delete",
                "object": "dir",
                "apis": [
                    "RemoveDirectoryA",
                    "RemoveDirectoryW"
                ],
                "args": [("file", "DirectoryName")]
            },
            {
                "event": "create",
                "object": "dir",
                "apis": [
                    "CreateDirectoryW",
                    "CreateDirectoryExW"
                ],
                "args": [("file", "DirectoryName")]
            },
            {
                "event": "write",
                "object": "file",
                "apis": [
                    "URLDownloadToFileW",
                    "URLDownloadToFileA"
                ],
                "args": [("file", "FileName")]
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "CreateProcessAsUserA",
                    "CreateProcessAsUserW",
                    "CreateProcessA",
                    "CreateProcessW",
                    "NtCreateProcess",
                    "NtCreateProcessEx"
                ],
                "args": [("file", "FileName")]
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "CreateProcessInternalW",
                ],
                "args": [("file", "CommandLine")]
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "ShellExecuteExA",
                    "ShellExecuteExW",
                ],
                "args": [("file", "FilePath")]
            },
            {
                "event": "load",
                "object": "library",
                "apis": [
                    "LoadLibraryA",
                    "LoadLibraryW",
                    "LoadLibraryExA",
                    "LoadLibraryExW",
                    "LdrLoadDll",
                    "LdrGetDllHandle"
                ],
                "args": [
                    ("file", "FileName"),
                    ("pathtofile", "PathToFile"),
                    ("moduleaddress", "BaseAddress")
                ]
            },
            {
                "event": "findwindow",
                "object": "windowname",
                "apis": [
                    "FindWindowA",
                    "FindWindowW",
                    "FindWindowExA",
                    "FindWindowExW"
                ],
                "args": [
                    ("classname", "ClassName"),
                    ("windowname", "WindowName")
                ]
            },
            {
                "event": "read",
                "object": "file",
                "apis": [
                    "NtReadFile",
                    "ReadFile"
                ],
                "args": []
            },
            {
                "event": "write",
                "object": "file",
                "apis": ["NtWriteFile"],
                "args": []
            },
            {
                "event": "delete",
                "object": "registry",
                "apis": [
                    "RegDeleteKeyA",
                    "RegDeleteKeyW"
                ],
                "args": []
            },
            {
                "event": "write",
                "object": "registry",
                "apis": [
                    "RegSetValueExA",
                    "RegSetValueExW"
                ],
                "args": [
                    ("content", "Buffer"),
                    ("object", "object")
                ]
            },
            {
                "event": "read",
                "object": "registry",
                "apis": [
                    "RegQueryValueExA",
                    "RegQueryValueExW",
                    "NtQueryValueKey"
                ],
                "args": []
            },
            {
                "event": "delete",
                "object": "registry",
                "apis": [
                    "RegDeleteValueA",
                    "RegDeleteValueW",
                    "NtDeleteValueKey"
                ],
                "args": []
            },
            {
                "event": "create",
                "object": "windowshook",
                "apis": ["SetWindowsHookExA"],
                "args": [
                    ("id", "HookIdentifier"),
                    ("moduleaddress", "ModuleAddress"),
                    ("procedureaddress", "ProcedureAddress")
                ]
            },
            {
                "event": "modify",
                "object": "service",
                "apis": ["ControlService"],
                "args": [("controlcode", "ControlCode")]
            },
            {
                "event": "delete",
                "object": "service",
                "apis": ["DeleteService"],
                "args": [],
            },
        ]

        # Not sure I really want this, way too noisy anyway and doesn't bring
        # much value.
        #if self.details:
        #    gendata = gendata + [{"event" : "get",
        #           "object" : "procedure",
        #           "apis" : ["LdrGetProcedureAddress"],
        #           "args": [("name", "FunctionName"), ("ordinal", "Ordinal")]
        #          },]

        event = _generic_handle(self, gendat, call)
        args = _load_args(call)

        if event:
            if call["api"] in ["NtReadFile", "ReadFile", "NtWriteFile"]:
                event["data"]["file"] = _get_handle(self.filehandles, args["FileHandle"])

            elif call["api"] in ["RegDeleteKeyA", "RegDeleteKeyW"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("Handle", "")), args.get("SubKey", ""))

            elif call["api"] in ["RegSetValueExA", "RegSetValueExW"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("Handle", "")), args.get("ValueName", ""))

            elif call["api"] in ["RegQueryValueExA", "RegQueryValueExW", "RegDeleteValueA", "RegDeleteValueW"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in ["NtQueryValueKey", "NtDeleteValueKey"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrGetDllHandle"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("ModuleHandle", ""))

            elif call["api"] in ["LdrLoadDll"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("BaseAddress", ""))

            elif call["api"] in ["LdrGetProcedureAddress"] and call["status"]:
                self._add_procedure(args.get("ModuleHandle", ""), args.get("FunctionName", ""), args.get("FunctionAddress", ""))
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleHandle", ""))

            elif call["api"] in ["SetWindowsHookExA"]:
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleAddress", ""))

            if call["api"] in ["ControlService", "DeleteService"]:
                event["data"]["service"] = _get_handle(self.servicehandles, args["ServiceHandle"])

            if call["api"] in ["ControlService"]:
                event["data"]["action"] = _get_service_action(args["ControlCode"])

            return event

        elif call["api"] in ["SetCurrentDirectoryA", "SetCurrentDirectoryW"]:
            self.currentdir = args["Path"]

        # Files
        elif call["api"] in ["NtCreateFile", "NtOpenFile"]:
            _add_handle(self.filehandles, args["FileHandle"], args["FileName"])

        elif call["api"] in ["CreateFileW"]:
            _add_handle(self.filehandles, call["return"], args["FileName"])

        elif call["api"] in ["NtClose", "CloseHandle"]:
            _remove_handle(self.filehandles, args["Handle"])

        # Services
        elif call["api"] in ["OpenServiceW"]:
            _add_handle(self.servicehandles, call["return"], args["ServiceName"])

        # Registry
        elif call["api"] in ["RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW"]:
            self._add_keyhandle(args.get("Registry", ""), args.get("SubKey", ""), args.get("Handle", ""))

        elif call["api"] in ["NtOpenKey"]:
            self._add_keyhandle(None, args.get("ObjectAttributes", ""), args.get("KeyHandle", ""))

        elif call["api"] in ["RegCloseKey"]:
            self._remove_keyhandle(args.get("Handle", ""))

        return event

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """
        event = self._process_call(call)
        if event:
            self.events.append(event)

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, mutexes and files.
        """
        return self.events

class ProcessTree:
    """Generates process tree."""

    key = "processtree"

    def __init__(self):
        self.processes = []
        self.tree = []

    def add_node(self, node, tree):
        """Add a node to a process tree.
        @param node: node to add.
        @param tree: processes tree.
        @return: boolean with operation success status.
        """
        # Walk through the existing tree.
        for process in tree:
            # If the current process has the same ID of the parent process of
            # the provided one, append it the children.
            if process["pid"] == node["parent_id"]:
                process["children"].append(node)
            # Otherwise try with the children of the current process.
            else:
                self.add_node(node, process["children"])

    def event_apicall(self, call, process):
        for entry in self.processes:
            if entry["pid"] == process["process_id"]:
                return

        self.processes.append(dict(
            name=process["process_name"],
            pid=process["process_id"],
            parent_id=process["parent_id"],
            children=[]
        ))

    def run(self):
        children = []

        # Walk through the generated list of processes.
        for process in self.processes:
            has_parent = False
            # Walk through the list again.
            for process_again in self.processes:
                # If we find a parent for the first process, we mark it as
                # as a child.
                if process_again["pid"] == process["parent_id"]:
                    has_parent = True

            # If the process has a parent, add it to the children list.
            if has_parent:
                children.append(process)
            # Otherwise it's an orphan and we add it to the tree root.
            else:
                self.tree.append(process)

        # Now we loop over the remaining child processes.
        for process in children:
            self.add_node(process, self.tree)

        return self.tree

class BehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    key = "behavior"

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        behavior = {}
        behavior["processes"] = Processes(self.logs_path).run()

        instances = [
            ProcessTree(),
            Summary(),
            Enhanced(),
        ]

        # Iterate calls and tell interested signatures about them
        for process in behavior["processes"]:
            for call in process["calls"]:
                for instance in instances:
                    try:
                        instance.event_apicall(call, process)
                    except:
                        log.exception("Failure in partial behavior \"%s\"", instance.key)

        for instance in instances:
            try:
                behavior[instance.key] = instance.run()
            except:
                log.exception("Failed to run partial behavior class \"%s\"", instance.key)

            # Reset the ParseProcessLog instances after each module
            for process in behavior["processes"]:
                process["calls"].reset()

        return behavior
