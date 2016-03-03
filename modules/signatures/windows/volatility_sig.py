# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VolMalfind1(Signature):
    name = "volatility_malfind_2"
    description = "Malfind detects one or more injected processes"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "2.0"

    def on_complete(self):
        pids = set()
        for row in self.get_volatility("malfind").get("data", []):
            pids.add(row["process_id"])

        if pids:
            self.mark_vol("malfind", pidcount=len(pids))

        return self.has_marks()

class VolLdrModules1(Signature):
    name = "volatility_ldrmodules_1"
    description = "PEB modified to hide loaded modules. " \
        "Dll very likely not loaded by LoadLibrary"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "2.0"

    # http://mnin.blogspot.de/2011/06/examining-stuxnets-footprint-in-memory.html

    def on_complete(self):
        exceptions = ["csrss.exe"]

        for row in self.get_volatility("ldrmodules").get("data", []):
            if not row["dll_in_init"] and not row["dll_in_load"] and \
                    not row["dll_in_mem"] and \
                    not row["process_name"].lower() in exceptions:
                self.mark_vol("unlinked", dll=row)

        return self.has_marks()

class VolLdrModules2(Signature):
    name = "volatility_ldrmodules_2"
    description = "PEB modified to hide loaded modules.\
         Not path name. Dll very likely not loaded by LoadLibrary"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "2.0"

    # http://mnin.blogspot.de/2011/06/examining-stuxnets-footprint-in-memory.html

    def on_complete(self):
        for row in self.get_volatility("ldrmodules").get("data", []):
            if not row["process_name"]:
                self.mark_vol("unlinked", dll=row)

        return self.has_marks()

class VolDevicetree1(Signature):
    name = "volatility_devicetree_1"
    description = "Device driver without name"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "2.0"

    # http://mnin.blogspot.de/2011/10/zeroaccess-volatility-and-kernel-timers.html

    def on_complete(self):
        for row in self.get_volatility("devicetree").get("data", []):
            if not row["driver_name"]:
                self.mark_vol("unnamed_driver", driver=row)

        return self.has_marks()

class VolSvcscan1(Signature):
    name = "volatility_svcscan_1"
    description = "Stopped Firewall service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "2.0"

    def on_complete(self):
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "SharedAccess" and \
                    row["service_state"] == "SERVICE_STOPPED":
                self.mark_vol("stopped_service", service=row)

        return self.has_marks()

class VolSvcscan2(Signature):
    name = "volatility_svcscan_2"
    description = "Stopped Security Center service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "2.0"

    def on_complete(self):
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "wscsvc" and \
                    row["service_state"] == "SERVICE_STOPPED":
                self.mark_vol("stopped_service", service=row)

        return self.has_marks()

class VolSvcscan3(Signature):
    name = "volatility_svcscan_3"
    description = "Stopped Application Layer Gateway service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "2.0"

    def on_complete(self):
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "ALG" and \
                    row["service_state"] == "SERVICE_STOPPED":
                self.mark_vol("stopped_service", service=row)

        return self.has_marks()

class VolModscan1(Signature):
    name = "volatility_modscan_1"
    description = "Kernel module without a name"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "2.0"

    def on_complete(self):
        for row in self.get_volatility("modscan").get("data", []):
            if not row["kernel_module_name"]:
                self.mark_vol("mysterious_kernel_module", kernel_module=row)

        return self.has_marks()

class VolHandles1(Signature):
    name = "volatility_handles_1"
    description = "One or more thread handles in other processes"
    severity = 2
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "2.0"

    def on_complete(self):
        threads = set()

        for row in self.get_volatility("handles").get("data", []):
            if row["handle_type"] == "Thread":
                w1, t1, w2, p1 = row["handle_name"].split(" ")
                if int(p1) != row["process_id"]:
                    threads.add("%d -> %s/%s" % (row["process_id"], p1, t1))

        if threads:
            self.mark_vol("injections", threads=list(threads))

        return self.has_marks()
