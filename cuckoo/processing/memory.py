# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import time
import socket
import shutil
import psutil

from cuckoo.common.abstracts import Processing
from cuckoo.common.config import config
from cuckoo.common.exceptions import (
    CuckooStartupError, CuckooOperationalError
)
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

try:
    import volatility.conf as conf
    import volatility.registry as registry
    import volatility.commands as commands
    import volatility.utils as utils
    import volatility.plugins.malware.devicetree as devicetree
    import volatility.plugins.malware.apihooks as apihooks
    import volatility.plugins.getsids as sidm
    import volatility.plugins.privileges as privm
    import volatility.plugins.taskmods as taskmods
    import volatility.win32.tasks as tasks
    import volatility.obj as obj
    import volatility.exceptions as exc
    import volatility.plugins.filescan as filescan
    import volatility.protos as protos
    import volatility.plugins.linux.common as linux_common

    HAVE_VOLATILITY = True

    # Inherit Cuckoo debugging level for Volatility commands.
    rootlogger = logging.getLogger()
    logging.getLogger("volatility.debug").setLevel(rootlogger.level)
    logging.getLogger("volatility.obj").setLevel(rootlogger.level)
    logging.getLogger("volatility.utils").setLevel(rootlogger.level)
except ImportError as e:
    if e.message == "No module named Crypto.Hash":
        raise CuckooStartupError(
            "Could not load Volatility: the PyCrypto package is missing "
            "(install with `pip install pycrypto`)"
        )

    if e.message.startswith("No module named volatility"):
        HAVE_VOLATILITY = False
    else:
        raise
except NameError as e:
    if "distorm3" in e.message:
        raise CuckooStartupError(
            "Could not load Volatility: the distorm3 package is missing "
            "(install with `pip install distorm3`)"
        )
    raise

def s(o):
    if isinstance(o, obj.NoneObject):
        return None
    return str(o)

class VolatilityAPI(object):
    """ Volatility API interface."""

    def __init__(self, memdump, osprofile):
        """@param memdump: the memdump file path
        @param osprofile: the profile (OS type)
        """
        registry.PluginImporter()
        self.memdump = memdump
        self.osprofile = osprofile
        self.config = None
        self.addr_space = None
        self.profiles = registry.get_plugin_classes(obj.Profile).keys()
        self.init_config()

    def get_dtb(self):
        """Use psscan to get system dtb and apply it."""
        ps = filescan.PSScan(self.config)

        for ep in ps.calculate():
            if str(ep.ImageFileName) == "System":
                self.config.update("dtb", ep.Pcb.DirectoryTableBase)
                return True

        return False

    def init_config(self):
        """Create a volatility configuration."""
        if self.config is not None and self.addr_space is not None:
            return

        if not self.osprofile:
            raise CuckooOperationalError(
                "Can't continue to process the VM memory dump if no OS "
                "profile has been defined for it. One may define its OS "
                "profile using the 'osprofile' field for the VM in its "
                "machinery configuration or set a global default using "
                "'guest_profile' in memory.conf"
            )

        if self.osprofile not in self.profiles:
            raise CuckooOperationalError(
                "The profile '%s' does not exist! Please pick one of the "
                "following profiles for your VMs: %s" %
                (self.osprofile, ", ".join(sorted(self.profiles)))
            )

        self.config = conf.ConfObject()
        self.config.optparser.set_conflict_handler("resolve")
        registry.register_global_options(self.config, commands.Command)

        base_conf = {
            "profile": self.osprofile,
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
            "location": "file://%s" % self.memdump,
            "plugins": None,
            "debug": None,
            "cache_dtb": True,
            "filename": None,
            "cache_directory": None,
            "verbose": None,
            "write": False
        }

        for key, value in base_conf.items():
            self.config.update(key, value)

        # Deal with Volatility support for KVM/qemu memory dump.
        # See: #464.
        try:
            self.addr_space = utils.load_as(self.config)
        except exc.AddrSpaceError as e:
            if self.get_dtb():
                self.addr_space = utils.load_as(self.config)
            elif "No suitable address space mapping found" in e.message:
                raise CuckooOperationalError(
                    "An incorrect OS has been specified for this machine! "
                    "Please provide the correct one or Cuckoo won't be able "
                    "to provide Volatility-based results for analyses with "
                    "this VM."
                )
            else:
                raise

        self.plugins = (
            registry.get_plugin_classes(commands.Command, lower=True)
        )

    def pslist(self):
        """Volatility pslist plugin.
        @see volatility/plugins/taskmods.py
        """
        results = []

        command = taskmods.PSList(self.config)
        for process in command.calculate():
            results.append({
                "process_name": str(process.ImageFileName),
                "process_id": int(process.UniqueProcessId),
                "parent_id": int(process.InheritedFromUniqueProcessId),
                "num_threads": str(process.ActiveThreads),
                "num_handles": s(process.ObjectTable.HandleCount),
                "session_id": s(process.SessionId),
                "create_time": str(process.CreateTime or ""),
                "exit_time": str(process.ExitTime or ""),
            })

        return dict(config={}, data=results)

    def _get_task_vals(self, task):
        if task.parent.is_valid():
            ppid       = str(task.parent.pid)
        else:
            ppid       = "-"

        uid = task.uid
        if uid == None or uid > 10000:
            uid = "-"

        gid = task.gid
        if gid == None or gid > 100000:
            gid = "-"

        start_time = task.get_task_start_time()
        if start_time == None:
            start_time = "-"

        if task.mm.pgd == None:
            dtb = None
        else:
            dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd

        task_offset = None
        if hasattr(self, "wants_physical") and task.obj_vm.base:
            task_offset = self.addr_space.vtop(task.obj_offset)

        if task_offset == None:
            task_offset = task.obj_offset

        return task_offset, dtb, ppid, uid, gid, str(start_time)

    def linux_pslist(self):
        """Volatility pslist plugin.
        @see volatility/plugins/taskmods.py
        """
        results = []

        command = self.plugins["linux_pslist"](self.config)
        for task in command.calculate():
            task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)
            results.append({
                "process_name": str(task.comm),
                "process_id": str(task.pid),
                "parent_id": str(ppid),
                "uid": str(uid),
                "gid": str(gid),
                "DTB": str(dtb),
                "create_time": str(start_time or "")
            })

        return dict(config={}, data=results)

    def psxview(self):
        """Volatility psxview plugin.
        @see volatility/plugins/malware/psxview.py
        """
        results = []

        command = self.plugins["psxview"](self.config)
        for offset, process, ps_sources in command.calculate():
            results.append({
                "process_name": str(process.ImageFileName),
                "process_id": int(process.UniqueProcessId),
                "pslist": str(offset in ps_sources["pslist"]),
                "psscan": str(offset in ps_sources["psscan"]),
                "thrdproc": str(offset in ps_sources["thrdproc"]),
                "pspcid": str(offset in ps_sources["pspcid"]),
                "csrss": str(offset in ps_sources["csrss"]),
                "session": str(offset in ps_sources["session"]),
                "deskthrd": str(offset in ps_sources["deskthrd"]),
            })

        return dict(config={}, data=results)

    def linux_psxview(self):
        """Volatility psxview plugin.
        @see volatility/plugins/malware/psxview.py
        """
        results = []

        command = self.plugins["linux_psxview"](self.config)
        for offset, process, ps_sources in command.calculate():
            results.append({
                #"offset": str(offset),
                "process_name": str(process.comm),
                "process_id": str(process.pid),
                "pslist": str(offset in ps_sources["pslist"]),
                "psscan": str(offset in ps_sources["psscan"]),
                "pid_hash": str(offset in ps_sources["pid_hash"]),
                "kmem_cache": str(offset in ps_sources["kmem_cache"]),
                "parents": str(offset in ps_sources["parents"]),
                "thread_leaders": str(offset in ps_sources["thread_leaders"]),
            })

        return dict(config={}, data=results)

    def malconfscan(self):
        """ Volatility malconfscan plugin
        https://github.com/JPCERTCC/MalConfScan
        @see volatility/plugins/malware/malconfscan.py
        """
        results = []
        malconf = []
        command = self.plugins["malconfscan"](self.config)

        for task, vad_base_addr, end, hit, memory_model, config_data in command.calculate():

            # strip null bytes and convert dict data to list data.
            for i in range(len(config_data)):
                conf = []
                for field, value in config_data[i].iteritems():
                    value = str(value).strip(chr(0))
                    config_data[i][field]= value
                    conf.append({
                        field: value
                        })
                malconf.append(conf)

            results.append({
                "process_name": str(task.ImageFileName),
                "process_id": str(task.UniqueProcessId),
                "malware_name": str(hit),
                "vad_base_addr": '0x' + str(vad_base_addr).zfill(8),
                "size": '0x' + str(end - vad_base_addr + 1).zfill(8),
                "malconf": malconf,
            })

        return dict(config={}, data=results)

    def callbacks(self):
        """Volatility callbacks plugin.
        @see volatility/plugins/malware/callbacks.py
        """
        results = []

        command = self.plugins["callbacks"](self.config)
        for (sym, cb, detail), mods, mod_addrs in command.calculate():
            module = tasks.find_module(
                mods, mod_addrs, self.addr_space.address_mask(cb)
            )

            if module:
                module_name = module.BaseDllName or module.FullDllName
            else:
                module_name = "UNKNOWN"

            results.append({
                "type": str(sym),
                "module": str(module_name),
                "details": str(detail or "-"),
            })

        return dict(config={}, data=results)

    def idt(self):
        """Volatility idt plugin.
        @see volatility/plugins/malware/idt.py
        """
        results = []

        command = self.plugins["idt"](self.config)
        for n, entry, addr, module in command.calculate():
            if module:
                module_name = str(module.BaseDllName or "")
                sect_name = command.get_section_name(module, addr)
            else:
                module_name = "UNKNOWN"
                sect_name = ""

            # The parent is IDT. The grand-parent is _KPCR.
            cpu_number = entry.obj_parent.obj_parent.ProcessorBlock.Number
            results.append({
                "cpu_number": int(cpu_number),
                "index": int(n),
                "selector": hex(int(entry.Selector)),
                "address": hex(int(addr)),
                "module": module_name,
                "section": sect_name,
            })

        return dict(config={}, data=results)

    def linux_check_idt(self):
        """Volatility idt plugin.
        @see volatility/plugins/malware/idt.py
        """
        results = []

        command = self.plugins["linux_check_idt"](self.config)
        for (i, _, idt_addr, sym_name, hooked) in command.calculate():
            results.append({
                "index": str(i),
                "address": str(idt_addr),
                "module": str(sym_name)
            })

        return dict(config={}, data=results)

    def linux_mount(self):
        """Volatility idt plugin.
        @see volatility/plugins/malware/idt.py
        """
        results = []

        command = self.plugins["linux_mount"](self.config)
        for (_sb, dev_name, path, fstype, rr, mnt_string) in command.calculate():
            results.append({
                "dev_name": str(dev_name),
                "path": str(path),
                "fstype": str(fstype),
                "rr": str(rr),
                "mnt_string": str(mnt_string)
            })

        return dict(config={}, data=results)

    def linux_check_modules(self):
        """Volatility idt plugin.
        @see volatility/plugins/malware/idt.py
        """
        results = []

        command = self.plugins["linux_check_modules"](self.config)
        for mod in command.calculate():
            results.append({
                "Module_Address": str(mod),
                "Core_Address": str(mod.module_core),
                "Init_Address": str(mod.module_init),
                "Module_Name": str(mod.name)
            })

        return dict(config={}, data=results)

    def gdt(self):
        """Volatility gdt plugin.
        @see volatility/plugins/malware/idt.py
        """
        results = []

        command = self.plugins["gdt"](self.config)
        # Comment: this code is pretty much ripped from
        # render_text in volatility.
        for n, entry in command.calculate():
            selector = n * 8

            # Is the entry present? This applies to all types of GDT entries
            if entry.Present:
                present = "P"
            else:
                present = "Np"

            # The base, limit, and granularity is calculated differently
            # for 32bit call gates than they are for all other types.
            if entry.Type == "CallGate32":
                base = entry.CallGate
                limit = 0
                granularity = "-"
            else:
                base = entry.Base
                limit = entry.Limit
                if entry.Granularity:
                    granularity = "Pg"
                else:
                    granularity = "By"

            # The parent is GDT. The grand-parent is _KPCR.
            cpu_number = entry.obj_parent.obj_parent.ProcessorBlock.Number

            results.append({
                "cpu_number": int(cpu_number),
                "selector": hex(selector),
                "base": hex(int(base)),
                "limit": hex(int(limit)),
                "type": str(entry.Type),
                "dpl": str(entry.Dpl),
                "granularity": granularity,
                "present": present,
            })

        return dict(config={}, data=results)

    def ssdt(self):
        """Volatility ssdt plugin.
        @see volatility/plugins/ssdt.py
        """
        results = []

        command = self.plugins["ssdt"](self.config)

        # Comment: this code is pretty much ripped from
        # render_text in volatility.
        syscalls = self.addr_space.profile.syscalls
        bits32 = self.addr_space.profile.metadata.get(
            "memory_model", "32bit"
        ) == "32bit"

        for idx, table, n, vm, mods, mod_addrs in command.calculate():
            for i in range(n):
                if bits32:
                    # These are absolute function addresses in kernel memory.
                    syscall_addr = obj.Object(
                        "address", table + (i * 4), vm
                    ).v()
                else:
                    # These must be signed long for x64 because they are RVAs
                    # relative to the base of the table and can be negative.
                    offset = obj.Object("long", table + (i * 4), vm).v()
                    # The offset is the top 20 bits of the 32 bit number.
                    syscall_addr = table + (offset >> 4)

                try:
                    syscall_name = syscalls[idx][i]
                except IndexError:
                    syscall_name = "UNKNOWN"

                syscall_mod = tasks.find_module(
                    mods, mod_addrs,
                    self.addr_space.address_mask(syscall_addr)
                )
                if syscall_mod:
                    syscall_modname = "{0}".format(syscall_mod.BaseDllName)
                else:
                    syscall_modname = "UNKNOWN"

                new = {
                    "index": int(idx),
                    "table": "0x%x" % int(table),
                    "entry": "{0:#06x}".format(idx * 0x1000 + i),
                    "syscall_name": syscall_name,
                    "syscall_addr": "0x%x" % int(syscall_addr),
                    "syscall_modname": syscall_modname,
                }

                if bits32 and syscall_mod is not None:
                    ret = apihooks.ApiHooks.check_inline(
                        va=syscall_addr, addr_space=vm,
                        mem_start=syscall_mod.DllBase,
                        mem_end=syscall_mod.DllBase + syscall_mod.SizeOfImage)

                    # Could not analyze the memory.
                    if ret is not None:
                        hooked, data, dest_addr = ret
                        if hooked:
                            # We found a hook, try to resolve the hooker.
                            # No mask required because we currently only work
                            # on x86 anyway.
                            hook_mod = tasks.find_module(
                                mods, mod_addrs, dest_addr
                            )
                            if hook_mod:
                                hook_name = "{0}".format(hook_mod.BaseDllName)
                            else:
                                hook_name = "UNKNOWN"

                            # Report it now.
                            new.update({
                                "hook_dest_addr": "{0:#x}".format(dest_addr),
                                "hook_name": hook_name,
                            })

                results.append(new)

        return dict(config={}, data=results)

    def timers(self):
        """Volatility timers plugin.
        @see volatility/plugins/malware/timers.py
        """
        results = []

        command = self.plugins["timers"](self.config)
        for timer, module in command.calculate():
            if timer.Header.SignalState.v():
                signaled = "Yes"
            else:
                signaled = "-"

            if module:
                module_name = str(module.BaseDllName or "")
            else:
                module_name = "UNKNOWN"

            due_time = "{0:#010x}:{1:#010x}".format(
                timer.DueTime.HighPart, timer.DueTime.LowPart
            )

            results.append({
                "offset": hex(timer.obj_offset),
                "due_time": due_time,
                "period": int(timer.Period),
                "signaled": signaled,
                "routine": hex(int(timer.Dpc.DeferredRoutine)),
                "module": module_name,
            })

        return dict(config={}, data=results)

    def messagehooks(self):
        """Volatility messagehooks plugin.
        @see volatility/plugins/malware/messagehooks.py
        """
        results = []

        command = self.plugins["messagehooks"](self.config)
        for winsta, atom_tables in command.calculate():
            for desk in winsta.desktops():
                for name, hook in desk.hooks():
                    module = command.translate_hmod(
                        winsta, atom_tables, hook.ihmod
                    )
                    results.append({
                        "offset": hex(int(hook.obj_offset)),
                        "session": int(winsta.dwSessionId),
                        "desktop": "{0}\\{1}".format(winsta.Name, desk.Name),
                        "thread": "<any>",
                        "filter": str(name),
                        "flags": str(hook.flags),
                        "function": hex(int(hook.offPfn)),
                        "module": str(module),
                    })

                for thrd in desk.threads():
                    info = "{0} ({1} {2})".format(
                        thrd.pEThread.Cid.UniqueThread,
                        thrd.ppi.Process.ImageFileName,
                        thrd.ppi.Process.UniqueProcessId)

                    for name, hook in thrd.hooks():
                        module = command.translate_hmod(
                            winsta, atom_tables, hook.ihmod
                        )
                        results.append({
                            "offset": hex(int(hook.obj_offset)),
                            "session": int(winsta.dwSessionId),
                            "desktop": "{0}\\{1}".format(
                                winsta.Name, desk.Name
                            ),
                            "thread": str(info),
                            "filter": str(name),
                            "flags": str(hook.flags),
                            "function": hex(int(hook.offPfn)),
                            "module": str(module),
                        })

        return dict(config={}, data=results)

    def getsids(self):
        """Volatility getsids plugin.
        @see volatility/plugins/malware/getsids.py
        """
        results = []

        command = self.plugins["getsids"](self.config)
        for task in command.calculate():
            token = task.get_token()

            if not token:
                continue

            for sid_string in token.get_sids():
                if sid_string in sidm.well_known_sids:
                    sid_name = " {0}".format(sidm.well_known_sids[sid_string])
                else:
                    sid_name_re = sidm.find_sid_re(
                        sid_string, sidm.well_known_sid_re
                    )
                    if sid_name_re:
                        sid_name = " {0}".format(sid_name_re)
                    else:
                        sid_name = ""

                results.append({
                    "filename": str(task.ImageFileName),
                    "process_id": int(task.UniqueProcessId),
                    "sid_string": str(sid_string),
                    "sid_name": str(sid_name),
                })

        return dict(config={}, data=results)

    def privs(self):
        """Volatility privs plugin.
        @see volatility/plugins/malware/privs.py
        """
        results = []

        command = self.plugins["privs"](self.config)

        for task in command.calculate():
            privileges = task.get_token().privileges()
            for value, present, enabled, default in privileges:
                try:
                    name, desc = privm.PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue

                attributes = []
                if present:
                    attributes.append("Present")
                if enabled:
                    attributes.append("Enabled")
                if default:
                    attributes.append("Default")

                results.append({
                    "process_id": int(task.UniqueProcessId),
                    "filename": str(task.ImageFileName),
                    "value": int(value),
                    "privilege": str(name),
                    "attributes": ",".join(attributes),
                    "description": str(desc),
                })

        return dict(config={}, data=results)

    def malfind(self, dump_dir=None):
        """Volatility malfind plugin.
        @param dump_dir: optional directory for dumps
        @see volatility/plugins/malware/malfind.py
        """
        results = []

        command = self.plugins["malfind"](self.config)
        for task in command.calculate():
            vads = task.get_vads(vad_filter=task._injection_filter)
            for vad, address_space in vads:
                if command._is_vad_empty(vad, address_space):
                    continue

                results.append({
                    "process_name": str(task.ImageFileName),
                    "process_id": int(task.UniqueProcessId),
                    "vad_start": "{0:#x}".format(vad.Start),
                    "vad_tag": str(vad.Tag),
                })

                if dump_dir:
                    filename = os.path.join(
                        dump_dir, "process.{0:#x}.{1:#x}.dmp".format(
                            task.obj_offset, vad.Start
                        )
                    )
                    command.dump_vad(filename, vad, address_space)

        return dict(config={}, data=results)

    def linux_malfind(self, dump_dir=None):
        """Volatility malfind plugin.
        @param dump_dir: optional directory for dumps
        @see volatility/plugins/malware/linux/malfind.py
        """
        results = []

        command = self.plugins["linux_malfind"](self.config)
        for task in command.calculate():
            proc_as = task.get_process_address_space()
            for vma in task.get_proc_maps():
                if vma.is_suspicious():
                    fname = vma.vm_name(task)
                    if fname == "[vdso]":
                        continue

                    prots = vma.protection()
                    flags = vma.flags()

                    content = proc_as.zread(vma.vm_start, 64)

                    hexdump = "".join(
                        "{0:#010x}  {1:<48}  {2}\n".format(vma.vm_start + o, h, ''.join(c))
                        for o, h, c in utils.Hexdump(content[0:64]))

                    results.append({
                        "process_name": str(task.comm),
                        "process_id": str(task.pid),
                        "vm_start": str(vma.vm_start),
                        "fname": str(fname),
                        "protection": str(prots),
                        "flags": str(flags),
                        "hexdump": hexdump
                    })

                # if dump_dir:
                #     filename = os.path.join(
                #         dump_dir, "process.{0:#x}.{1:#x}.dmp".format(
                #             task.comm, vma.vm_start
                #         )
                #     )
                #     command.dump_vad(filename, vad, address_space)

        return dict(config={}, data=results)

    def yarascan(self):
        """Volatility yarascan plugin.
        @see volatility/plugins/malware/yarascan.py
        """
        results = []

        yarapath = cwd("stuff", "index_memory.yar")
        if not os.path.exists(yarapath):
            return dict(config={}, data=[])

        self.config.update("YARA_FILE", yarapath)

        command = self.plugins["yarascan"](self.config)
        for o, addr, hit, content in command.calculate():
            # Comment: this code is pretty much ripped from
            # render_text in volatility.
            # Find out if the hit is from user or kernel mode
            if o is None:
                owner = "Unknown Kernel Memory"
            elif o.obj_name == "_EPROCESS":
                owner = "Process {0} Pid {1}".format(
                    o.ImageFileName, o.UniqueProcessId
                )
            else:
                owner = "{0}".format(o.BaseDllName)

            hexdump = "".join(
                "{0:#010x}  {1:<48}  {2}\n".format(addr + o, h, ''.join(c))
                for o, h, c in utils.Hexdump(content[0:64]))

            results.append({
                "rule": hit.rule,
                "owner": owner,
                "hexdump": hexdump,
            })

        return dict(config={}, data=results)

    def linux_yarascan(self):
        """Volatility yarascan plugin.
        @see volatility/plugins/malware/yarascan.py
        """
        results = []

        yarapath = cwd("stuff", "index_memory.yar")
        if not os.path.exists(yarapath):
            return dict(config={}, data=[])

        self.config.update("YARA_FILE", yarapath)

        command = self.plugins["linux_yarascan"](self.config)
        for task, address, hit, buf in command.calculate():
            # Comment: this code is pretty much ripped from
            # render_text in volatility.
            # Find out if the hit is from user or kernel mode
            hexdump = "".join(
                "{0:#010x}  {1:<48}  {2}\n".format(address + o, h, ''.join(c))
                for o, h, c in utils.Hexdump(buf[0:64]))
            if task:
                results.append({
                    "rule": str(hit.rule),
                    "owner": "Task: {0} pid {1}".format(task.comm, task.pid),
                    "addr": str(address),
                    "hexdump": hexdump
                })
            else:
                results.append({
                    "rule": str(hit.rule),
                    "addr": str(address),
                    "hexdump": hexdump
                })
        return dict(config={}, data=results)

    def apihooks(self):
        """Volatility apihooks plugin.
        @see volatility/plugins/malware/apihooks.py
        """
        results = []

        command = self.plugins["apihooks"](self.config)
        for process, module, hook in command.calculate():
            proc_name = str(process.ImageFileName) if process else ''
            if command.whitelist(hook.hook_mode | hook.hook_type,
                                 proc_name, hook.VictimModule,
                                 hook.HookModule, hook.Function):
                continue

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

    def linux_apihooks(self):
        """Volatility apihooks plugin.
        @see volatility/plugins/malware/apihooks.py
        """
        results = []

        command = self.plugins["linux_apihooks"](self.config)
        for task in command.calculate():
            for hook_desc, sym_name, addr, hook_type, hook_addr, hookfuncdesc in task.apihook_info():
                proc_name = str(task.comm)
                if command.whitelist(hook_desc | hook_type,
                                     proc_name, sym_name,
                                     addr, hookfuncdesc):
                    continue
                new = {
                    "process_id" : str(task.pid),
                    "process_name" : str(task.comm),
                    "hook_vma": str(hook_desc),
                    "hook_symbol": str(sym_name),
                    "hooked_address": addr,
                    "hook_address": hook_addr,
                    "type": hook_type,
                    "hook_address": hookfuncdesc
                }

                results.append(new)

        return dict(config={}, data=results)

    def dlllist(self):
        """Volatility dlllist plugin.
        @see volatility/plugins/taskmods.py
        """
        results = []

        command = self.plugins["dlllist"](self.config)
        for task in command.calculate():
            new = {
                "process_id": int(task.UniqueProcessId),
                "process_name": str(task.ImageFileName),
                "commandline": str(
                    task.Peb.ProcessParameters.CommandLine or ""
                ),
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
        results = []

        command = self.plugins["handles"](self.config)
        for pid, handle, object_type, name in command.calculate():
            results.append({
                "process_id": int(pid),
                "handle_value": str(handle.HandleValue),
                "handle_granted_access": str(handle.GrantedAccess),
                "handle_type": str(object_type),
                "handle_name": str(name)
            })

        return dict(config={}, data=results)

    def ldrmodules(self):
        """Volatility ldrmodules plugin.
        @see volatility/plugins/malware/malfind.py
        """
        results = []

        command = self.plugins["ldrmodules"](self.config)
        for task in command.calculate():
            # Build a dictionary for all three PEB lists where the
            # keys are base address and module objects are the values.
            inloadorder = dict(
                (mod.DllBase.v(), mod) for mod in task.get_load_modules()
            )
            ininitorder = dict(
                (mod.DllBase.v(), mod) for mod in task.get_init_modules()
            )
            inmemorder = dict(
                (mod.DllBase.v(), mod) for mod in task.get_mem_modules()
            )

            # Build a similar dictionary for the mapped files.
            mapped_files = {}
            vads = task.get_vads(vad_filter=task._mapped_file_filter)
            for vad, address_space in vads:
                # Note this is a lot faster than acquiring the full
                # vad region and then checking the first two bytes.
                o = obj.Object(
                    "_IMAGE_DOS_HEADER", offset=vad.Start, vm=address_space
                )
                if o.e_magic != 0x5A4D:
                    continue

                mapped_files[int(vad.Start)] = str(
                    vad.FileObject.FileName or ""
                )

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
                    "dll_in_load": load_mod is not None,
                    "dll_in_init": init_mod is not None,
                    "dll_in_mem": mem_mod is not None,
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

    def linux_ldrmodules(self):
        """Volatility ldrmodules plugin.
        @see volatility/plugins/malware/malfind.py
        """
        results = []

        command = self.plugins["linux_ldrmodules"](self.config)
        for task in command.calculate():
            for vm_start, vma_name, pmaps, dmaps in task.ldrmodules():
                results.append({
                    "process_id": str(task.pid),
                    "process_name": str(task.comm),
                    "vm_start": str(vm_start),
                    "vma_name": str(vma_name),
                    "pmaps": str(pmaps),
                    "dmaps": str(dmaps)
                })

        return dict(config={}, data=results)

    def linux_tmpfs(self):
        """Volatility ldrmodules plugin.
        @see volatility/plugins/linux/tmpfs.py
        not working: https://github.com/volatilityfoundation/volatility/issues/532
        """
        results = []

        #self.config.update('SB', '5')
        #self.config.update('DUMP_DIR', '/tmp/tmpfs')
        command = self.plugins["linux_tmpfs"](self.config)
        for (i, path) in command.calculate():
            results.append({
                    "i": str(i),
                    "path": str(path)
            })

        return dict(config={}, data=results)

    def linux_lsof(self):
        """Volatility ldrmodules plugin.
        @see volatility/plugins/malware/malfind.py
        """
        results = []

        command = self.plugins["linux_lsof"](self.config)
        for task in command.calculate():
            for filp, fd in task.lsof():
                results.append({
                    "offset": str(task.obj_offset),
                    "process_id": str(task.pid),
                    "process_name": str(task.comm),
                    "fd": str(fd),
                    "path": str(linux_common.get_path(task, filp))
                })

        return dict(config={}, data=results)

    def mutantscan(self):
        """Volatility mutantscan plugin.
        @see volatility/plugins/filescan.py
        """
        results = []

        command = self.plugins["mutantscan"](self.config)
        for mutant in command.calculate():
            header = mutant.get_object_header()
            tid = 0
            pid = 0
            if mutant.OwnerThread > 0x80000000:
                thread = mutant.OwnerThread.dereference_as("_ETHREAD")
                tid = thread.Cid.UniqueThread
                pid = thread.Cid.UniqueProcess

            results.append({
                "mutant_offset": "{0:#x}".format(mutant.obj_offset),
                "num_pointer": int(header.PointerCount),
                "num_handles": int(header.HandleCount),
                "mutant_signal_state": str(mutant.Header.SignalState),
                "mutant_name": str(header.NameInfo.Name or ""),
                "process_id": int(pid),
                "thread_id": int(tid)
            })

        return dict(config={}, data=results)

    def devicetree(self):
        """Volatility devicetree plugin.
        @see volatility/plugins/malware/devicetree.py
        """
        results = []

        command = self.plugins["devicetree"](self.config)
        for driver_obj in command.calculate():
            new = {
                "driver_offset": "0x{0:08x}".format(driver_obj.obj_offset),
                "driver_name": str(driver_obj.DriverName or ""),
                "devices": []
            }

            for device in driver_obj.devices():
                body_offset = device.obj_vm.profile.get_obj_offset(
                    "_OBJECT_HEADER", "Body"
                )
                device_header = obj.Object(
                    "_OBJECT_HEADER",
                    offset=device.obj_offset - body_offset,
                    vm=device.obj_vm,
                    native_vm=device.obj_native_vm
                )

                device_name = str(device_header.NameInfo.Name or "")

                new_device = {
                    "device_offset": "0x{0:08x}".format(device.obj_offset),
                    "device_name": device_name,
                    "device_type": devicetree.DEVICE_CODES.get(
                        device.DeviceType.v(), "UNKNOWN"
                    ),
                    "devices_attached": []
                }

                new["devices"].append(new_device)

                level = 0

                for att_device in device.attached_devices():
                    body_offset = att_device.obj_vm.profile.get_obj_offset(
                        "_OBJECT_HEADER", "Body"
                    )
                    device_header = obj.Object(
                        "_OBJECT_HEADER",
                        offset=att_device.obj_offset - body_offset,
                        vm=att_device.obj_vm,
                        native_vm=att_device.obj_native_vm
                    )

                    device_name = str(device_header.NameInfo.Name or "")
                    name = "%s - %s" % (
                        device_name,
                        str(att_device.DriverObject.DriverName or "")
                    )

                    device_type = devicetree.DEVICE_CODES.get(
                        att_device.DeviceType.v(), "UNKNOWN"
                    )
                    new_device["devices_attached"].append({
                        "level": level,
                        "attached_device_offset": "0x{0:08x}".format(
                            att_device.obj_offset
                        ),
                        "attached_device_name": name,
                        "attached_device_type": device_type,
                    })

                    level += 1

            results.append(new)

        return dict(config={}, data=results)

    def svcscan(self):
        """Volatility svcscan plugin - scans for services.
        @see volatility/plugins/malware/svcscan.py
        """
        results = []

        command = self.plugins["svcscan"](self.config)
        for rec in command.calculate():
            results.append({
                "service_offset": "{0:#x}".format(rec.obj_offset),
                "service_order": int(rec.Order),
                "process_id": int(rec.Pid),
                "service_name": str(rec.ServiceName.dereference()),
                "service_display_name": str(rec.DisplayName.dereference()),
                "service_type": str(rec.Type),
                "service_binary_path": s(rec.Binary),
                "service_state": str(rec.State)
            })

        return dict(config={}, data=results)

    def modscan(self):
        """Volatility modscan plugin.
        @see volatility/plugins/modscan.py
        """
        results = []

        command = self.plugins["modscan"](self.config)
        for ldr_entry in command.calculate():
            results.append({
                "kernel_module_offset": "{0:#x}".format(ldr_entry.obj_offset),
                "kernel_module_name": str(ldr_entry.BaseDllName or ""),
                "kernel_module_file": str(ldr_entry.FullDllName or ""),
                "kernel_module_base": "{0:#x}".format(ldr_entry.DllBase),
                "kernel_module_size": int(ldr_entry.SizeOfImage),
            })

        return dict(config={}, data=results)

    def imageinfo(self):
        """Volatility imageinfo plugin.
        @see volatility/plugins/imageinfo.py
        """
        results = []

        command = self.plugins["imageinfo"](self.config)
        new = {}
        for key, value in command.calculate():
            new[key] = value

        osp = new["Suggested Profile(s)"].split(",")[0]
        new["osprofile"] = osp
        results.append(new)

        return dict(config={}, data=results)

    def sockscan(self):
        """Volatility sockscan plugin.
        @see volatility/plugins/sockscan.py
        """
        results = []

        command = self.plugins["sockscan"](self.config)
        for sock in command.calculate():
            results.append({
                "offset": "{0:#010x}".format(sock.obj_offset),
                "process_id": str(sock.Pid),
                "address": str(sock.LocalIpAddress),
                "port": str(sock.LocalPort),
                "protocol": "{0} ({1})".format(
                    sock.Protocol, protos.protos.get(sock.Protocol.v(), "-")
                ),
                "create_time": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.gmtime(int(sock.CreateTime))
                ),
            })

        return dict(config={}, data=results)

    def netscan(self):
        """Volatility sockscan plugin.
        @see volatility/plugins/netscan.py
        """
        results = []

        commands = self.plugins["netscan"](self.config).calculate()
        for net_obj, proto, laddr, lport, raddr, rport, state in commands:
            results.append({
                "offset": "{0:#010x}".format(net_obj.obj_offset),
                "process_id": str(net_obj.Owner.UniqueProcessId),
                "local_address": s(laddr),
                "local_port": str(lport),
                "remote_address": s(raddr),
                "remote_port": str(rport),
                "protocol": str(proto),
            })

        return dict(config={}, data=results)

    def linux_netscan(self):
        """Volatility sockscan plugin.
        @see volatility/plugins/netscan.py
        """
        results = []

        commands = self.plugins["linux_netscan"](self.config).calculate()
        for net_obj, proto, laddr, lport, raddr, rport, state in commands:
            results.append({
                "offset": "{0:#010x}".format(net_obj.obj_offset),
                "process_id": str(net_obj),
                "local_address": str(laddr),
                "local_port": str(lport),
                "remote_address": str(raddr),
                "remote_port": str(rport),
                "protocol": str(proto),
            })

        return dict(config={}, data=results)

    def linux_netstat(self):
        """Volatility sockscan plugin.
        @see volatility/plugins/netscan.py
        """
        results = []

        commands = self.plugins["linux_netstat"](self.config).calculate()
        for task in commands:
            for ents in task.netstat():
                if ents[0] == socket.AF_INET:
                    (_, proto, saddr, sport, daddr, dport, state) = ents[1]
                    results.append({
                        "protocol": str(proto),
                        "source_address": str(saddr),
                        "source_port": str(sport),
                        "destination_address": str(daddr),
                        "destination_port": str(dport),
                        "state": str(state),
                        "process_id" : str(task.pid),
                        "process_name" : str(task.comm),
                        "name": "-"
                    })

                elif ents[0] == 1 and not self.config.IGNORE_UNIX:
                    (name, inum) = ents[1]
                    results.append({
                        "protocol": str("UNIX "+str(inum)),
                        "source_address": "-",
                        "source_port": "-",
                        "destination_address": "-",
                        "destination_port": "-",
                        "state": "-",
                        "process_id" : str(task.pid),
                        "process_name" : str(task.comm),
                        "name": str(name)
                    })

        return dict(config={}, data=results)

class VolatilityManager(object):
    """Handle several volatility results."""
    PLUGINS = [
        "pslist",
        "psxview",
        "malconfscan",
        "callbacks",
        ["idt", "x86"],
        "ssdt",
        ["gdt", "x86"],
        "timers",
        "messagehooks",
        "getsids",
        "privs",
        "malfind",
        "apihooks",
        "dlllist",
        "handles",
        "ldrmodules",
        "mutantscan",
        "devicetree",
        "svcscan",
        "modscan",
        "yarascan",
        ["sockscan", "winxp"],
        ["netscan", "vista", "win7"],
    ]
    LINUX_PLUGINS = [
        "linux_pslist",
        "linux_psxview",
        "linux_malfind",
        "linux_apihooks",
        "linux_mount",
        "linux_check_modules",
        "linux_ldrmodules",
        "linux_check_idt",
        "linux_netstat",
        "linux_yarascan",
        "linux_netscan",
        "linux_lsof",
        "linux_tmpfs",
    ]

    def __init__(self, memfile, osprofile, platform):
        self.mask_pid = []
        self.taint_pid = set()
        self.memfile = memfile
        self.osprofile = osprofile
        self.platform = platform

        for pid in config("memory:mask:pid_generic"):
            if pid and pid.isdigit():
                self.mask_pid.append(int(pid))

        self.vol = VolatilityAPI(self.memfile, self.osprofile)

    def get_osprofile(self):
        """Get the OS profile"""
        return self.vol.imageinfo()["data"][0]["osprofile"]

    def enabled(self, plugin_name, profiles):
        # Some plugins can only run in certain profiles (i.e., only in
        # Windows XP/Vista/7, or only in x86 or x64).
        osprofile = self.osprofile.lower()
        for profile in profiles:
            if osprofile.startswith(profile) or osprofile.endswith(profile):
                break
        else:
            if profiles:
                return False

        if not config("memory:%s:enabled" % plugin_name):
            log.debug("Skipping '%s' volatility module", plugin_name)
            return False

        if plugin_name not in self.vol.plugins:
            return False

        return True

    def run(self):
        results = {}
        platform = self.platform.lower()
        if platform == "linux":
            plugins = self.LINUX_PLUGINS
        else:
            plugins = self.PLUGINS

        for plugin_name in plugins:
            if isinstance(plugin_name, list):
                plugin_name, profiles = plugin_name[0], plugin_name[1:]
            else:
                profiles = []

            if not self.enabled(plugin_name, profiles):
                continue

            log.debug("Executing volatility '%s' module.", plugin_name)
            results[plugin_name] = getattr(self.vol, plugin_name)()

        self.find_taint(results)
        self.cleanup()
        return self.mask_filter(results)

    def mask_filter(self, old):
        """Filter out masked stuff. Keep tainted stuff."""
        new = {}

        for akey in old.keys():
            new[akey] = {"config": old[akey]["config"], "data": []}
            do_filter = config("memory:%s:filter" % akey)
            new[akey]["config"]["filter"] = do_filter
            for item in old[akey]["data"]:
                # TODO: need to improve this logic.
                if not do_filter:
                    new[akey]["data"].append(item)
                elif "process_id" in item and \
                        item["process_id"] in self.mask_pid and \
                        item["process_id"] not in self.taint_pid:
                    pass
                else:
                    new[akey]["data"].append(item)
        return new

    def find_taint(self, res):
        """Find tainted items."""
        for item in res.get("malfind", {}).get("data", []):
            self.taint_pid.add(item["process_id"])

    def cleanup(self):
        """Delete the memory dump (if configured to do so)."""
        if config("memory:basic:delete_memdump"):
            try:
                os.remove(self.memfile)
            except OSError:
                log.error(
                    "Unable to delete memory dump file at path \"%s\"",
                    self.memfile
                )

class Memory(Processing):
    """Volatility Analyzer."""

    def run(self):
        """Run analysis.
        @return: volatility results dict.
        """
        self.key = "memory"

        if not HAVE_VOLATILITY:
            log.error(
                "Cannot run volatility module: the volatility library "
                "is not available. Please install it according to their "
                "documentation."
            )
            return

        if not self.memory_path or not os.path.exists(self.memory_path):
            log.error(
                "VM memory dump not found: to create VM memory dumps you "
                "have to enable memory_dump in cuckoo.conf!"
            )
            return

        if not os.path.getsize(self.memory_path):
            log.error(
                "VM memory dump empty: to properly create VM memory dumps "
                "you have to enable memory_dump in cuckoo.conf!"
            )
            return

        osprofile = (
            self.machine.get("osprofile") or None
            #or config("memory:basic:guest_profile")
        )

        platform = (
            self.machine.get("platform") or None
             #or config("memory:basic:platform")
        )
        #log.debug(str(self.machine))
        #workaround for multi machinery
        if not platform:
            if self.machine.get("name").startswith("Ubuntu"):
                platform = "linux"
                osprofile = "LinuxUbuntu1904x64"
            elif self.machine.get("name").startswith("Mac"):
                platform = "darwin"
                osprofile = "Mac10_14_2_18C54x64"
            else:
                osprofile = config("memory:basic:guest_profile")
                platform = "windows"

        try:
            if config("cuckoo:ramfs:enabled"):
                space_available = psutil.disk_usage(config("cuckoo:ramfs:path")).free >> 20
                ramfs_path = os.path.join(config("cuckoo:ramfs:path"), str(self.task.id) + ".dmp")
                if space_available > config("cuckoo:ramfs:freespace"):
                    shutil.copy(self.memory_path,ramfs_path)
                return VolatilityManager(ramfs_path, osprofile, platform).run()
            else:
                return VolatilityManager(self.memory_path, osprofile, platform).run()
        except Exception as e:
            log.error(
                "Error running Volatility on machine '%s %s': %s",
                (self.machine.get("name") or "unknown VM name"), osprofile, e, exc_info=True
            )
        finally:
            if config("cuckoo:ramfs:enabled"):
                try:
                    if os.path.exists(ramfs_path):
                        os.remove(ramfs_path)
                except OSError:
                    log.error(
                        "Unable to delete memory dump file at ramfs \"%s\"",
                        ramfs_path
                    )
                if config("memory:basic:delete_memdump"):
                    try:
                        if os.path.exists(self.memory_path):
                            os.remove(self.memory_path)
                    except OSError:
                        log.error(
                            "Unable to delete memory dump file at path \"%s\"",
                            self.memory_path
                        )
