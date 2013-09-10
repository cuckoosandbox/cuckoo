# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config

try:
    import volatility.conf as conf
    import volatility.registry as registry
    import volatility.commands as commands
    import volatility.win32.network as network
    import volatility.utils as utils
    import volatility.plugins.malware.malfind as malfind
    import volatility.plugins.malware.devicetree as devicetree
    import volatility.plugins.taskmods as taskmods
    import volatility.obj as obj
    HAVE_VOLATILITY = True
except ImportError:
    HAVE_VOLATILITY = False

log = logging.getLogger(__name__)

class VolatilityAPI(object):
    """ Volatility API interface."""

    def __init__(self, memdump, osprofile=None):
        """@param memdump: the memdump file path
        @param osprofile: the profile (OS type)
        """
        registry.PluginImporter()
        self.memdump = memdump
        self.osprofile = osprofile
        self.config = None
        self.__config()

    def __config(self):
        """Creates a volatility configuration."""
        self.config = conf.ConfObject()
        self.config.optparser.set_conflict_handler("resolve")
        registry.register_global_options(self.config, commands.Command)
        base_conf = {
            "profile": "WinXPSP2x86",
            "use_old_as": None,
            "kdbg": None,
            "help": False,
            "kpcr": None,
            "tz": None,
            "pid": None,
            "output_file": None,
            "physical_offset": None,
            "conf_file": None,
            "dtb": None,
            "output": None,
            "info": None,
            "location": "file://" + self.memdump,
            "plugins": None,
            "debug": None,
            "cache_dtb": True,
            "filename": None,
            "cache_directory": None,
            "verbose": None,
            "write": False
        }

        if self.osprofile:
            base_conf["profile"] = self.osprofile

        for key, value in base_conf.items():
            self.config.update(key, value)

        self.addr_space = utils.load_as(self.config)
        self.plugins = registry.get_plugin_classes(commands.Command, lower=True)

        return self.config

    def pslist(self):
        """Volatility pslist plugin.
        @see volatility/plugins/taskmods.py
        """
        log.debug("Executing Volatility pslist plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = taskmods.PSList(self.config)
        for process in command.calculate():
            new = {
                "process_name": str(process.ImageFileName),
                "process_id": int(process.UniqueProcessId),
                "parent_id": int(process.InheritedFromUniqueProcessId),
                "num_threads": str(process.ActiveThreads),
                "num_handles": str(process.ObjectTable.HandleCount),
                "session_id": str(process.SessionId),
                "create_time": str(process.CreateTime or ""),
                "exit_time": str(process.ExitTime or ""),
            }

            results.append(new)

        return dict(config={}, data=results)

    def malfind(self, dump_dir=None):
        """Volatility malfind plugin.
        @param dump_dir: optional directory for dumps
        @see volatility/plugins/malware/malfind.py
        """
        log.debug("Executing Volatility malfind plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["malfind"](self.config)
        for task in command.calculate():
            for vad, address_space in task.get_vads(vad_filter=task._injection_filter):
                if command._is_vad_empty(vad, address_space):
                    continue

                new = {
                    "process_name": str(task.ImageFileName),
                    "process_id": int(task.UniqueProcessId),
                    "vad_start": "{0:#x}".format(vad.Start),
                    "vad_tag": str(vad.Tag),
                }

                results.append(new)

                if dump_dir:
                    filename = os.path.join(dump_dir, "process.{0:#x}.{1:#x}.dmp".format(task.obj_offset, vad.Start))
                    command.dump_vad(filename, vad, address_space)

        return dict(config={}, data=results)

    def apihooks(self):
        """Volatility apihooks plugin.
        @see volatility/plugins/malware/apihooks.py
        """
        log.debug("Executing Volatility apihooks plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["apihooks"](self.config)
        for process, module, hook in command.calculate():
            new = {
                "hook_mode": str(hook.Mode),
                "hook_type": str(hook.Type),
                "victim_module": str(module.BaseDllName or ""),
                "victim_function": str(hook.Detail),
                "hook_address": "{0:#x}".format(hook.hook_address),
                "hooking_module": str(hook.HookModule)
            }

            if process:
                new["process_id"] = int(process.UniqueProcessId)
                new["process_name"] = str(process.ImageFileName)

            results.append(new)

        return dict(config={}, data=results)

    def dlllist(self):
        """Volatility dlllist plugin.
        @see volatility/plugins/taskmods.py
        """
        log.debug("Executing Volatility dlllist plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["dlllist"](self.config)
        for task in command.calculate():
            new = {
                "process_id": int(task.UniqueProcessId),
                "process_name": str(task.ImageFileName),
                "commandline": str(task.Peb.ProcessParameters.CommandLine or ""),
                "loaded_modules": []
            }

            for module in task.get_load_modules():
                new["loaded_modules"].append({
                    "dll_base": str(module.DllBase),
                    "dll_size": str(module.SizeOfImage),
                    "dll_full_name": str(module.FullDllName or ""),
                    "dll_load_count": int(module.LoadCount),
                })

            results.append(new)

        return dict(config={}, data=results)

    def handles(self):
        """Volatility handles plugin.
        @see volatility/plugins/handles.py
        """
        log.debug("Executing Volatility handles plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["handles"](self.config)
        for pid, handle, object_type, name in command.calculate():
            new = {
                "process_id": int(pid),
                "handle_value": str(handle.HandleValue),
                "handle_granted_access": str(handle.GrantedAccess),
                "handle_type": str(object_type),
                "handle_name": str(name)
            }

            results.append(new)

        return dict(config={}, data=results)

    def ldrmodules(self):
        """Volatility ldrmodules plugin.
        @see volatility/plugins/malware/malfind.py
        """
        log.debug("Executing Volatility ldrmodules plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["ldrmodules"](self.config)
        for task in command.calculate():
            # Build a dictionary for all three PEB lists where the
            # keys are base address and module objects are the values.
            inloadorder = dict((mod.DllBase.v(), mod) for mod in task.get_load_modules())
            ininitorder = dict((mod.DllBase.v(), mod) for mod in task.get_init_modules())
            inmemorder = dict((mod.DllBase.v(), mod) for mod in task.get_mem_modules())

            # Build a similar dictionary for the mapped files.
            mapped_files = {}
            for vad, address_space in task.get_vads(vad_filter=task._mapped_file_filter):
                # Note this is a lot faster than acquiring the full
                # vad region and then checking the first two bytes.
                if obj.Object("_IMAGE_DOS_HEADER", offset=vad.Start, vm=address_space).e_magic != 0x5A4D:
                    continue

                mapped_files[int(vad.Start)] = str(vad.FileObject.FileName or "")

            # For each base address with a mapped file, print info on
            # the other PEB lists to spot discrepancies.
            for base in mapped_files.keys():
                # Does the base address exist in the PEB DLL lists?
                load_mod = inloadorder.get(base, None)
                init_mod = ininitorder.get(base, None)
                mem_mod = inmemorder.get(base, None)

                new = {
                    "process_id": int(task.UniqueProcessId),
                    "process_name": str(task.ImageFileName),
                    "dll_base": "{0:#x}".format(base),
                    "dll_in_load": load_mod != None,
                    "dll_in_init": init_mod != None,
                    "dll_in_mem": mem_mod != None,
                    "dll_mapped_path": str(mapped_files[base]),
                    "load_full_dll_name": "",
                    "init_full_dll_name": "",
                    "mem_full_dll_name": ""
                }

                if load_mod:
                    new["load_full_dll_name"] = str(load_mod.FullDllName)

                if init_mod:
                    new["init_full_dll_name"] = str(init_mod.FullDllName)

                if mem_mod:
                    new["mem_full_dll_name"] = str(mem_mod.FullDllName)

                results.append(new)

        return dict(config={}, data=results)

    def mutantscan(self):
        """Volatility mutantscan plugin.
        @see volatility/plugins/filescan.py
        """
        log.debug("Executing Volatility mutantscan module on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["mutantscan"](self.config)
        for object_obj, mutant in command.calculate():
            tid = 0
            pid = 0
            if mutant.OwnerThread > 0x80000000:
                thread = mutant.OwnerThread.dereference_as("_ETHREAD")
                tid = thread.Cid.UniqueThread
                pid = thread.Cid.UniqueProcess

            new = {
                "mutant_offset": "{0:#x}".format(mutant.obj_offset),
                "num_pointer": int(object_obj.PointerCount),
                "num_handles": int(object_obj.HandleCount),
                "mutant_signal_state": str(mutant.Header.SignalState),
                "mutant_name": str(object_obj.NameInfo.Name or ""),
                "process_id": int(pid),
                "thread_id": int(tid)
            }

            results.append(new)

        return dict(config={}, data=results)

    def devicetree(self):
        """Volatility devicetree plugin.
        @see volatility/plugins/malware/devicetree.py
        """
        log.debug("Executing Volatility devicetree module on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["devicetree"](self.config)
        for _object_obj, driver_obj, _ in command.calculate():
            new = {
                "driver_offset": "0x{0:08x}".format(driver_obj.obj_offset),
                "driver_name": str(driver_obj.DriverName or ""),
                "devices": []
            }

            for device in driver_obj.devices():
                device_header = obj.Object(
                    "_OBJECT_HEADER",
                    offset=device.obj_offset - device.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                    vm=device.obj_vm,
                    native_vm=device.obj_native_vm
                )

                device_name = str(device_header.NameInfo.Name or "")

                new_device = {
                    "device_offset": "0x{0:08x}".format(device.obj_offset),
                    "device_name": device_name,
                    "device_type": devicetree.DEVICE_CODES.get(device.DeviceType.v(), "UNKNOWN"),
                    "devices_attached": []
                }

                new["devices"].append(new_device)

                level = 0

                for att_device in device.attached_devices():
                    device_header = obj.Object(
                        "_OBJECT_HEADER",
                        offset = att_device.obj_offset - att_device.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                        vm = att_device.obj_vm,
                        native_vm = att_device.obj_native_vm
                    )

                    device_name = str(device_header.NameInfo.Name or "")
                    name = (device_name + " - " + str(att_device.DriverObject.DriverName or ""))

                    new_device["devices_attached"].append({
                        "level": level,
                        "attached_device_offset": "0x{0:08x}".format(att_device.obj_offset),
                        "attached_device_name": name,
                        "attached_device_type": devicetree.DEVICE_CODES.get(att_device.DeviceType.v(), "UNKNOWN")
                    })

                    level += 1

            results.append(new)

        return dict(config={}, data=results)

    def svcscan(self):
        """Volatility svcscan plugin - scans for services.
        @see volatility/plugins/malware/svcscan.py
        """
        log.debug("Executing Volatility svcscan plugin on {0}".format(self.memdump))
        
        self.__config()
        results = []
        
        command = self.plugins["svcscan"](self.config)
        for rec in command.calculate():
            new = {
                "service_offset": "{0:#x}".format(rec.obj_offset),
                "service_order": int(rec.Order),
                "process_id": int(rec.Pid),
                "service_name": str(rec.ServiceName.dereference()),
                "service_display_name": str(rec.DisplayName.dereference()),
                "service_type": str(rec.Type),
                "service_binary_path": str(rec.Binary),
                "service_state": str(rec.State)
            }

            results.append(new)

        return dict(config={}, data=results)

    def modscan(self):
        """Volatility modscan plugin.
        @see volatility/plugins/modscan.py
        """
        log.debug("Executing Volatility modscan plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["modscan"](self.config)
        for ldr_entry in command.calculate():
            new = {
                "kernel_module_offset": "{0:#x}".format(ldr_entry.obj_offset),
                "kernel_module_name": str(ldr_entry.BaseDllName or ""),
                "kernel_module_file": str(ldr_entry.FullDllName or ""),
                "kernel_module_base": "{0:#x}".format(ldr_entry.DllBase),
                "kernel_module_size": int(ldr_entry.SizeOfImage),
            }

            results.append(new)

        return dict(config={}, data=results)

    def imageinfo(self):
        """Volatility imageinfo plugin.
        @see volatility/plugins/imageinfo.py
        """
        log.debug("Executing Volatility imageinfo plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["imageinfo"](self.config)
        new = {}
        for key, value in command.calculate():
            new[key] = value

        osp = new["Suggested Profile(s)"].split(",")[0]
        new["osprofile"] = osp

        results.append(new)

        return dict(config={}, data=results)

class VolatilityManager(object):
    """Handle several volatility results."""

    def __init__(self, memfile, osprofile=None):
        self.mask_pid = []
        self.taint_pid = set()
        self.memfile = memfile

        conf_path = os.path.join(CUCKOO_ROOT, "conf", "memory.conf")
        if not os.path.exists(conf_path):
            log.error("Configuration file volatility.conf not found".format(conf_path))
            self.voptions = False
            return

        self.voptions = Config(conf_path)

        for pid in self.voptions.mask.pid_generic.split(","):
            pid = pid.strip()
            if pid:
                self.mask_pid.append(int(pid))

        self.no_filter = not self.voptions.mask.enabled
        self.osprofile = osprofile or self.get_osprofile()

    def get_osprofile(self):
        """Get the OS profile"""        
        return VolatilityAPI(self.memfile).imageinfo()["data"][0]["osprofile"] 

    def run(self):
        results = {}

        # Exit if options were not loaded.
        if not self.voptions:
            return

        vol = VolatilityAPI(self.memfile, self.osprofile)

        # TODO: improve the load of volatility functions.
        if self.voptions.pslist.enabled:
            results["pslist"] = vol.pslist()
        if self.voptions.malfind.enabled:
            results["malfind"] = vol.malfind()
        if self.voptions.apihooks.enabled:
            results["apihooks"] = vol.apihooks()
        if self.voptions.dlllist.enabled:
            results["dlllist"] = vol.dlllist()
        if self.voptions.handles.enabled:
            results["handles"] = vol.handles()
        if self.voptions.ldrmodules.enabled:
            results["ldrmodules"] = vol.ldrmodules()
        if self.voptions.mutantscan.enabled:
            results["mutantscan"] = vol.mutantscan()
        if self.voptions.devicetree.enabled:
            results["devicetree"] = vol.devicetree()
        if self.voptions.svcscan.enabled:
            results["svcscan"] = vol.svcscan()
        if self.voptions.modscan.enabled:
            results["modscan"] = vol.modscan()

        self.find_taint(results)
        self.cleanup()

        return self.mask_filter(results)

    def mask_filter(self, old):
        """Filter out masked stuff. Keep tainted stuff."""
        new = {}

        for akey in old.keys():
            new[akey] = {"config": old[akey]["config"], "data": []}
            conf = getattr(self.voptions, akey, None)
            new[akey]["config"]["filter"] = conf.filter
            for item in old[akey]["data"]:
                # TODO: need to improve this logic.
                if not conf.filter:
                    new[akey]["data"].append(item)
                elif ("process_id" in item and item["process_id"] in self.mask_pid and not item["process_id"] in self.taint_pid):
                    pass
                else:
                    new[akey]["data"].append(item)
        return new

    def find_taint(self, res):
        """Find tainted items."""
        if "malfind" in res:
            for item in res["malfind"]["data"]:
                self.taint_pid.add(item["process_id"])

    def cleanup(self):
        """Delete the memory dump (if configured to do so)."""

        if self.voptions.basic.delete_memdump:
            try:
                os.remove(self.memfile)
            except OSError as e:
                log.error("Unable to delete memory dump file at path \"%s\" ", self.memfile)

class Memory(Processing):
    """Volatility Analyzer."""

    def run(self):
        """Run analysis.
        @return: volatility results dict.
        """
        self.key = "memory"

        results = {}
        if HAVE_VOLATILITY:
            if self.memory_path and os.path.exists(self.memory_path):
                try:
                    vol = VolatilityManager(self.memory_path)
                    results = vol.run()
                except Exception as e:
                    log.exception("Generic error executing volatility")
            else:
                log.error("Memory dump not found: to run volatility you have to enable memory_dump")
        else:
            log.error("Cannot run volatility module: volatility library not available")

        return results
