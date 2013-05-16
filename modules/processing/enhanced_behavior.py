# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Processing
from behavior import Processes, ParseProcessLog

class BEvents:
    """
    The essence of behavior events
    """

    def __init__(self, proc_results, details = False):
        """

        @param proc_results: enumerated processes results.
        @param details: Also add some (not so relevant) Details to the log

        """
        self.proc_results = proc_results
        self.currentdir = "c:"
        self.eid = 0
        self.details = details
        self.filehandles = {}
        self.keyhandles = {"0x80000000": "HKEY_CLASSES_ROOT\\",
                           "0x80000001": "HKEY_CURRENT_USER\\",
                           "0x80000002": "HKEY_LOCAL_MACHINE\\",
                           "0x80000003": "HKEY_USERS\\",
                           "0x80000004": "HKEY_PERFORMANCE_DATA\\",
                           "0x80000005": "HKEY_CURRENT_CONFIG\\",
                           "0x80000006": "HKEY_DYN_DATA\\"}
        self.modules = {}
        self.procedures = {}

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, mutexes and files.
        """
        events = []

        for entry in self.proc_results:
            for call in entry["calls"]:
                evt = self._process_call(call)
                if evt:
                    events.append(evt)

        return events

    def _add_procedure(self, mbase, name, base):
        """
        Add a procedure address
        """
        self.procedures[base] = self._get_loaded_module(mbase) + ":" + name

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
                event = {"evt": item["evt"],
                         "obj": item["obj"],
                         "timestamp": call["timestamp"],
                         "eid": self.eid
                        }
                for (logname, dataname) in item["args"]:
                    event[logname] = args.get(dataname, None)
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
        # do generic handling
        gendat = [{"evt":"move",
                   "obj":"file",
                   "apis":["MoveFileWithProgressW", "MoveFileExA",
                        "MoveFileExW"],
                   "args":[("from", "ExistingFileName"), ("to", "NewFileName")]
                   },
                  {"evt":"copy",
                   "obj":"file",
                   "apis":["CopyFileA", "CopyFileW", "CopyFileExW",
                        "CopyFileExA"],
                   "args":[("from", "ExistingFileName"), ("to", "NewFileName")]
                  },
                  {"evt":"delete",
                   "obj":"file",
                   "apis":["DeleteFileA", "DeleteFileW", "NtDeleteFile"],
                   "args":[("file", "FileName")]
                  },
                  {"evt":"delete",
                   "obj":"dir",
                   "apis":["RemoveDirectoryA", "RemoveDirectoryW"],
                   "args":[("file", "DirectoryName")]
                  },
                  {"evt":"create",
                   "obj":"dir",
                   "apis":["CreateDirectoryW", "CreateDirectoryExW"],
                   "args":[("file", "DirectoryName")]
                  },
                  {"evt":"write",
                   "obj":"file",
                   "apis":["URLDownloadToFileW", "URLDownloadToFileA"],
                   "args":[("file", "FileName")]
                  },
                  {"evt":"execute",
                   "obj":"file",
                   "apis":["CreateProcessAsUserA", "CreateProcessAsUserW",
                            "CreateProcessA", "CreateProcessW",
                            "NtCreateProcess", "NtCreateProcessEx"],
                   "args":[("file", "FileName")]
                  },
                  {"evt":"load",
                   "obj":"library",
                   "apis":["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                            "LoadLibraryExW", "LdrLoadDll", "LdrGetDllHandle"],
                   "args":[("file", "FileName"),
                           ("pathtofile", "PathToFile"),
                           ("moduleaddress", "BaseAddress")]
                  },
                  {"evt":"findwindow",
                   "obj":"windowname",
                   "apis":["FindWindowA", "FindWindowW", "FindWindowExA",
                        "FindWindowExW"],
                   "args":[("classname", "ClassName"),
                           ("windowname", "WindowName")]
                  },
                  {"evt":"read",
                   "obj":"file",
                   "apis":["NtReadFile", "ReadFile"],
                   "args":[]
                  },
                  {"evt":"write",
                   "obj":"file",
                   "apis":["NtWriteFile"],
                   "args":[]
                  },
                  {"evt":"delete",
                   "obj":"registry",
                   "apis":["RegDeleteKeyA", "RegDeleteKeyW"],
                   "args":[]
                  },
                  {"evt":"write",
                   "obj":"registry",
                   "apis":["RegSetValueExA", "RegSetValueExW"],
                   "args":[("content", "Buffer"), ("type", "Type")]
                  },
                  {"evt":"read",
                   "obj":"registry",
                   "apis":["RegQueryValueExA", "RegQueryValueExW",
                        "NtQueryValueKey"],
                   "args":[]
                  },
                  {"evt":"delete",
                   "obj":"registry",
                   "apis":["RegDeleteValueA", "RegDeleteValueW",
                        "NtDeleteValueKey"],
                   "args":[]
                  },
                  {"evt":"create",
                   "obj":"windowshook",
                   "apis":["SetWindowsHookExA"],
                   "args":[("id", "HookIdentifier"),
                           ("moduleaddress", "ModuleAddress"),
                           ("procedureaddress", "ProcedureAddress")]
                  },                  
                ]

        if self.details:
            gendata = gendata + [{"evt":"get",
                   "obj":"procedure",
                   "apis": ["LdrGetProcedureAddress"],
                   "args": [("name", "FunctionName"), ("ordinal", "Ordinal")]
                  },]

        event = _generic_handle(self, gendat, call)
        # Add on data to generic handling goes here:
        # Additionally get the file handles for those:
        args = _load_args(call)
        if event:
            if call["api"] in ["NtReadFile", "ReadFile", "NtWriteFile"]:
                event["file"] = _get_file_handle(
                    self.filehandles, args["FileHandle"])
            elif call["api"] in ["RegDeleteKeyA", "RegDeleteKeyW"]:
                event["regkey"] = self._get_keyhandle(args.get("Handle", None)\
                    + args.get("SubKey", ""))
            elif call["api"] in ["RegSetValueExA", "RegSetValueExW"]:
                event["regkey"] = self._get_keyhandle(
                    args.get("Handle", None)) + args.get("ValueName", None)
            elif call["api"] in ["RegQueryValueExA", "RegQueryValueExW",
                    "RegDeleteValueA", "RegDeleteValueW", "NtDeleteValueKey"]:
                event["regkey"] = self._get_keyhandle(
                    args.get("Handle", "UNKNOWN")) +\
                    args.get("ValueName", None)
            elif call["api"] in ["NtQueryValueKey"]:
                event["regkey"] = self._get_keyhandle(
                    args.get("KeyHandle", "UNKNOWN")) +\
                    args.get("ValueName", None)
            elif call["api"] in ["LoadLibraryA",
                            "LoadLibraryW",
                            "LoadLibraryExA",
                            "LoadLibraryExW",
                            "LdrGetDllHandle"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""),\
                            args.get("ModuleHandle", ""))
            elif call["api"] in ["LdrLoadDll"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""),\
                            args.get("BaseAddress", ""))
            elif call["api"] in ["LdrGetProcedureAddress"] and call["status"]:
                self._add_procedure(args.get("ModuleHandle", ""),\
                            args.get("FunctionName", ""),
                            args.get("FunctionAddress", ""))
                event["module"] = self._get_loaded_module(
                            args.get("ModuleHandle", ""))
            elif call["api"] in ["SetWindowsHookExA"]:
                event["module"] = self._get_loaded_module(
                            args.get("ModuleAddress", ""))
            return event

        elif call["api"] in ["SetCurrentDirectoryA", "SetCurrentDirectoryW"]:
            self.currentdir = args["Path"]

        elif call["api"] in ["NtCreateFile", "NtOpenFile"]:
            _add_file_handle(self.filehandles,
                args["FileHandle"], args["FileName"])

        elif call["api"] in ["CreateFileW"]:
            _add_file_handle(self.filehandles,
                call["return"], args["FileName"])

        elif call["api"] in ["NtClose", "CloseHandle"]:
            _remove_file_handle(self.filehandles, args["Handle"])

        elif call["api"] in ["RegOpenKeyExA",
                             "RegOpenKeyExW",
                             "RegCreateKeyExA",
                             "RegCreateKeyExW"]:
            regkey = self._add_keyhandle(args.get("Registry", None),\
                args.get("SubKey", None), args.get("Handle", None))

        elif call["api"] in ["NtOpenKey"]:
            regkey = self._add_keyhandle(None,\
                args.get("ObjectAttributes", None),
                args.get("KeyHandle", None))

        elif call["api"] in ["RegCloseKey"]:
            regkey = self._remove_keyhandle(args.get("Handle", None))

        return event

class EnhancedBehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    order = 2

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "enhanced_behavior"
        details = self.options.get("details", None)
        if details:
            print "Details! "
        behavior = {}
        basic   = Processes(self.logs_path).run()
        behavior = BEvents(basic, details).run()

        return behavior
