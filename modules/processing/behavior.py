# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.utils import convert_to_printable, logtime
from lib.cuckoo.common.netlog import BsonParser
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

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
        self.parsecount = 0

        if os.path.exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

    def parse_first_and_reset(self):
        self.fd = open(self._log_path, "rb")
        if self._log_path.endswith(".bson"):
            self.parser = BsonParser(self)
        else:
            self.fd.close()
            self.fd = None
            return

        # should be the first two messages to get the process information
        self.parser.read_next_message()
        self.parser.read_next_message()
        self.fd.seek(0)

    def read(self, length):
        if length == 0: return b''
        buf = self.fd.read(length)
        if not buf or len(buf) != length: raise EOFError()
        return buf

    def __iter__(self):
        #import inspect
        #log.debug('iter called by this guy: {0}'.format(inspect.stack()[1]))
        return self

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return "ParseProcessLog {0}".format(self._log_path)

    def __nonzero__(self):
        return True

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
            try: r = self.parser.read_next_message()
            except EOFError:
                return False

            if not r:
                return False
        return True

    def next(self):
        if not self.fd: raise StopIteration()

        x = self.wait_for_lastcall()
        if not x:
            self.parsecount += 1
            self.fd.seek(0)
            raise StopIteration()

        nextcall, self.lastcall = self.lastcall, None

        x = self.wait_for_lastcall()
        while self.lastcall and self.compare_calls(nextcall, self.lastcall):
            nextcall["repeated"] += 1
            self.lastcall = None
            x = self.wait_for_lastcall()

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
                (arg_name, arg_value) = row[index]
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", row[index], e)
                continue

            argument["name"] = arg_name

            arg_value = str(arg_value)
            if arg_value[:4] == "\\??\\":
                arg_value = arg_value[4:]

            argument["value"] = convert_to_printable(arg_value)
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["thread_id"] = str(thread_id)
        call["category"] = category
        call["api"] = api_name
        call["status"] = bool(int(status_value))

        if isinstance(return_value, int):
            call["return"] = "0x%.08x" % return_value
        else:
            call["return"] = convert_to_printable(str(return_value))

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
            if current_log.process_id == None: continue

            # If the current log actually contains any data, add its data to
            # the global results list.
            results.append({
                "process_id": current_log.process_id,
                "process_name": current_log.process_name,
                "parent_id": current_log.parent_id,
                "first_seen": logtime(current_log.first_seen),
                "calls": current_log
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

        self.handles.append({"handle" : handle, "name" : name + subkey})
        return name + subkey

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
        elif call["api"].startswith("RegCloseKey"):
            handle = 0

            for argument in call["arguments"]:
                if argument["name"] == "Handle":
                    handle = int(argument["value"], 16)

            if handle != 0:
                try: self.handles.remove(handle)
                except ValueError: pass

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


class ProcessTree:
    """Creates process tree."""

    key = "processtree"

    def __init__(self):
        self.processes = []
        self.proctree = []
        self.procmap = {}

    def add_node(self, node, parent_id, tree):
        """Add a node to a tree.
        @param node: node to add.
        @param parent_id: parent node.
        @param tree: processes tree.
        @return: boolean with operation success status.
        """
        for process in tree:
            if process["pid"] == parent_id:
                new = {}
                new["name"] = node["name"]
                new["pid"] = node["pid"]
                new["children"] = []
                process["children"].append(new)
                return True
            self.add_node(node, parent_id, process["children"])
            
        return False

    def populate(self, node):
        """Populate tree.
        @param node: node to add.
        @return: True.
        """
        for children in node["children"]:
            for proc in self.processes:
                if int(proc["pid"]) == int(children):
                    self.add_node(proc, node["pid"], self.proctree)
                    self.populate(proc)

        return True

    def event_apicall(self, call, entry):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """
        pid = int(entry["process_id"])

        if not pid in self.procmap:
            process = {}
            process["name"] = entry["process_name"]
            process["pid"] = int(entry["process_id"])
            process["children"] = []
        
            self.procmap[pid] = process
            self.processes.append(process)
        else:
            process = self.procmap[pid]
        
        if call["api"] == "CreateProcessInternalW":
            for argument in call["arguments"]:
                if argument["name"] == "ProcessId":
                    process["children"].append(int(argument["value"]))

    def run(self):
        """Run analysis.
        @return: results dict or None.
        """
        if len(self.processes) > 0:    
            root = {}
            root["name"] = self.processes[0]["name"]
            root["pid"] = self.processes[0]["pid"]
            root["children"] = []
            self.proctree.append(root)
            self.populate(self.processes[0])

        return self.proctree

class Enhanced(object):

    key = "enhanced"

    def __init__(self, details=False):
        """
        @param details: Also add some (not so relevant) Details to the log
        """
        self.currentdir = "C: "
        self.eid = 0
        self.details = details
        self.filehandles = {}
        self.keyhandles = {
            "0x80000000" : "HKEY_CLASSES_ROOT\\",
            "0x80000001" : "HKEY_CURRENT_USER\\",
            "0x80000002" : "HKEY_LOCAL_MACHINE\\",
            "0x80000003" : "HKEY_USERS\\",
            "0x80000004" : "HKEY_PERFORMANCE_DATA\\",
            "0x80000005" : "HKEY_CURRENT_CONFIG\\",
            "0x80000006" : "HKEY_DYN_DATA\\"
        }
        self.modules = {}
        self.procedures = {}
        self.events = []

    def _add_procedure(self, mbase, name, base):
        """
        Add a procedure address
        """
        self.procedures[base] = "{0}:{1}".format(self._get_loaded_module(mbase), name)

    def _get_procedure(self, base):
        """
        Get the name of a procedure
        """
        return self.procedures.get(base, "")

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
        if registry and registry != "0x00000000" and\
            registry in self.keyhandles:
            name = self.keyhandles[registry]

        nkey = name + subkey
        nkey = self._fix_key(nkey)

        self.keyhandles[handle] = nkey

        return nkey

    def _remove_keyhandle(self, handle):
        key = self._get_keyhandle(handle)
        try:
            self.keyhandles.pop(handle)
        except KeyError:
            pass
        return key

    def _get_keyhandle(self, handle):
        try:
            return self.keyhandles[handle]
        except KeyError:
            return ""

    def _fix_key(self, key):
        """ Fix a registry key to have it normalized
        """
        res = key
        if key.lower().startswith("registry\\machine\\"):
            res = "HKEY_LOCAL_MACHINE\\" + key[17:]
        elif key.lower().startswith("registry\\user\\"):
            res = "HKEY_USERS\\" + key[14:]

        if not res.endswith("\\\\"):
            res = res + "\\"
        return res

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
                    "event" : item["event"],
                    "object" : item["object"],
                    "timestamp": call["timestamp"],
                    "eid": self.eid,
                    "data": {}
                }
                for (logname, dataname) in item["args"]:
                    event["data"][logname] = args.get(dataname, None)
                return event

        def _generic_handle(self, data, call):
            """
            Generic handling of api calls
            """
            for item in data:
                event = _generic_handle_details(self, call, item)
                if event:
                    return event

            return None

        # File handles
        def _add_file_handle(handles, handle, filename):
            handles[handle] = filename

        def _remove_file_handle(handles, handle):
            try:
                handles.pop(handle)
            except KeyError:
                pass

        def _get_file_handle(handles, handle):
            try:
                return handles[handle]
            except KeyError:
                return None

        event = None

        gendat = [
            {
                "event" : "move",
                "object" : "file",
                "apis" : [
                    "MoveFileWithProgressW",
                    "MoveFileExA",
                    "MoveFileExW"
                ],
                "args" : [
                    ("from", "ExistingFileName"),
                    ("to", "NewFileName")
                ]
            },
            {
                "event" : "copy",
                "object" : "file",
                "apis" : [
                    "CopyFileA",
                    "CopyFileW",
                    "CopyFileExW",
                    "CopyFileExA"
                ],
                "args" : [
                    ("from", "ExistingFileName"),
                    ("to", "NewFileName")
                ]
            },
            {
                "event" : "delete",
                "object" : "file",
                "apis" : [
                    "DeleteFileA",
                    "DeleteFileW",
                    "NtDeleteFile"
                ],
                "args" : [("file", "FileName")]
            },
            {
                "event" : "delete",
                "object" : "dir",
                "apis" : [
                    "RemoveDirectoryA",
                    "RemoveDirectoryW"
                ],
                "args" : [("file", "DirectoryName")]
            },
            {
                "event" : "create",
                "object" : "dir",
                "apis" : [
                    "CreateDirectoryW",
                    "CreateDirectoryExW"
                ],
                "args" : [("file", "DirectoryName")]
            },
            {
                "event" : "write",
                "object" : "file",
                "apis" : [
                    "URLDownloadToFileW",
                    "URLDownloadToFileA"
                ],
                "args" : [("file", "FileName")]
            },
            {
                "event" : "execute",
                "object" : "file",
                "apis" : [
                    "CreateProcessAsUserA",
                    "CreateProcessAsUserW",
                    "CreateProcessA",
                    "CreateProcessW",
                    "NtCreateProcess",
                    "NtCreateProcessEx"
                ],
                "args" : [("file", "FileName")]
            },
            {
                "event" : "load",
                "object" : "library",
                "apis" : [
                    "LoadLibraryA",
                    "LoadLibraryW",
                    "LoadLibraryExA",
                    "LoadLibraryExW",
                    "LdrLoadDll",
                    "LdrGetDllHandle"
                ],
                "args" : [
                    ("file", "FileName"),
                    ("pathtofile", "PathToFile"),
                    ("moduleaddress", "BaseAddress")
                ]
            },
            {
                "event" : "findwindow",
                "object" : "windowname",
                "apis" : [
                    "FindWindowA",
                    "FindWindowW",
                    "FindWindowExA",
                    "FindWindowExW"
                ],
                "args" : [
                    ("classname", "ClassName"),
                    ("windowname", "WindowName")
                ]
            },
            {
                "event" : "read",
                "object" : "file",
                "apis" : [
                    "NtReadFile",
                    "ReadFile"
                ],
                "args" : []
            },
            {
                "event" : "write",
                "object" : "file",
                "apis" : ["NtWriteFile"],
                "args" : []
            },
            {
                "event" : "delete",
                "object" : "registry",
                "apis" : [
                    "RegDeleteKeyA",
                    "RegDeleteKeyW"
                ],
                "args" : []
            },
            {
                "event" : "write",
                "object" : "registry",
                "apis" : [
                    "RegSetValueExA",
                    "RegSetValueExW"
                ],
                "args" : [
                    ("content", "Buffer"),
                    ("object", "object")
                ]
            },
            {
                "event" : "read",
                "object" : "registry",
                "apis" : [
                    "RegQueryValueExA",
                    "RegQueryValueExW",
                    "NtQueryValueKey"
                ],
                "args" : []
            },
            {
                "event" : "delete",
                "object" : "registry",
                "apis" : [
                    "RegDeleteValueA",
                    "RegDeleteValueW",
                    "NtDeleteValueKey"
                ],
                "args" : []
            },
            {
                "event" : "create",
                "object" : "windowshook",
                "apis" : ["SetWindowsHookExA"],
                "args" : [
                    ("id", "HookIdentifier"),
                    ("moduleaddress", "ModuleAddress"),
                    ("procedureaddress", "ProcedureAddress")
                ]
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
                event["data"]["file"] = _get_file_handle(self.filehandles, args["FileHandle"])

            elif call["api"] in ["RegDeleteKeyA", "RegDeleteKeyW"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("Handle", "")), args.get("SubKey", ""))

            elif call["api"] in ["RegSetValueExA", "RegSetValueExW"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("Handle", "")), args.get("ValueName", ""))

            elif call["api"] in ["RegQueryValueExA", "RegQueryValueExW", "RegDeleteValueA", "RegDeleteValueW", "NtDeleteValueKey"]:
                event["data"]["regkey"] = "{0}{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in ["NtQueryValueKey"]:
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

            return event

        elif call["api"] in ["SetCurrentDirectoryA", "SetCurrentDirectoryW"]:
            self.currentdir = args["Path"]

        elif call["api"] in ["NtCreateFile", "NtOpenFile"]:
            _add_file_handle(self.filehandles, args["FileHandle"], args["FileName"])

        elif call["api"] in ["CreateFileW"]:
            _add_file_handle(self.filehandles, call["return"], args["FileName"])

        elif call["api"] in ["NtClose", "CloseHandle"]:
            _remove_file_handle(self.filehandles, args["Handle"])

        elif call["api"] in ["RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW"]:
            regkey = self._add_keyhandle(args.get("Registry", ""), args.get("SubKey", ""), args.get("Handle", ""))

        elif call["api"] in ["NtOpenKey"]:
            regkey = self._add_keyhandle(None, args.get("ObjectAttributes", ""), args.get("KeyHandle", ""))

        elif call["api"] in ["RegCloseKey"]:
            regkey = self._remove_keyhandle(args.get("Handle", ""))

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

class BehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "behavior"

        behavior = {}
        behavior["processes"] = Processes(self.logs_path).run()

        instances = [
            ProcessTree(),
            Summary(),
            Enhanced(),
        ]

        # Iterate calls and tell interested signatures about them
        for proc in behavior["processes"]:
            for call in proc["calls"]:
                for i in instances:
                    try: r = i.event_apicall(call, proc)
                    except:
                        log.exception("Failure in partial behavior \"%s\"", i.key)

        for i in instances:
            try:
                behavior[i.key] = i.run()
            except:
                log.exception("Failed to run partial behavior class \"%s\"", i.key)

        return behavior
