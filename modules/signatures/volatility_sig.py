# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class VolMalfind1(Signature):
    name = "volatility_malfind_1"
    description = "Malfind detects an injected process"
    severity = 2
    alert = False
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "1.2"

    def run(self):
        if ("memory" in self.results and
            "malfind" in self.results["memory"]):
            if len(self.results["memory"]["malfind"]["data"]):
                self.add_match(None, "data", self.results["memory"]["malfind"]["data"])
                return True

        return False


class VolMalfind2(Signature):
    name = "volatility_malfind_2"
    description = "Malfind detects more than 3 injected processes"
    severity = 3
    alert = False   # Very suspicious, but has detection on clean files
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "1.2"
    families = ["ZBot", "Paelvo", "Sinowal"]

    def run(self):
        pids = set()
        if ("memory" in self.results and
            "malfind" in self.results["memory"]):
            for a in self.results["memory"]["malfind"]["data"]:
                pids.add(a["process_id"])
            if len(pids) > 3:
                self.add_match(None, "data", self.results["memory"]["malfind"]["data"])
                return True

        return False


class VolLdrModules1(Signature):
    name = "volatility_ldrmodules_1"
    description = "PEB modified to hide loaded\
             modules. Dll very likely not loaded by LoadLibrary"
    severity = 3
    alert = False   # Skype seems to do that...
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "1.2"

    # http://mnin.blogspot.de/2011/06/examining-stuxnets-footprint-in-memory.html

    def run(self):
        exceptions = ["csrss.exe"]

        if ("memory" in self.results and
            "ldrmodules" in self.results["memory"]):
            for d in self.results["memory"]["ldrmodules"]["data"]:
                if (not d["dll_in_init"] and
                    not d["dll_in_load"] and
                    not d["dll_in_mem"] and
                    not d["process_name"].lower() in exceptions):
                    self.add_match(None, "unlinked", d)

        return self.has_matches()


class VolLdrModules2(Signature):
    name = "volatility_ldrmodules_2"
    description = "PEB modified to hide loaded modules.\
         Not path name. Dll very likely not loaded by LoadLibrary"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "1.2"

    # http://mnin.blogspot.de/2011/06/examining-stuxnets-footprint-in-memory.html

    def run(self):
        if ("memory" in self.results and
            "ldrmodules" in self.results["memory"]):
            for d in self.results["memory"]["ldrmodules"]["data"]:
                if d["process_name"] == "":
                    self.add_match(None, "unlinked", d)

        return self.has_matches()


class VolDevicetree1(Signature):
    name = "volatility_devicetree_1"
    description = "Device driver without name"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "1.2"

    # http://mnin.blogspot.de/2011/10/zeroaccess-volatility-and-kernel-timers.html

    def run(self):
        if ("memory" in self.results and
            "devicetree" in self.results["memory"]):
            for d in self.results["memory"]["devicetree"]["data"]:
                if d["driver_name"] == "":
                    self.add_match(None, "unnamed_driver", d)

        return self.has_matches()


class VolSvcscan1(Signature):
    name = "volatility_svcscan_1"
    description = "Stopped Firewall service"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "1.2"

    def run(self):
        if ("memory" in self.results and
            "svcscan" in self.results["memory"]):
            for s in self.results["memory"]["svcscan"]["data"]:
                if (s["service_name"] == "SharedAccess" and
                    s["service_state"] == "SERVICE_STOPPED"):
                    self.add_match(None, "stopped_service", s)

        return self.has_matches()


class VolSvcscan2(Signature):
    name = "volatility_svcscan_2"
    description = "Stopped Security Center service"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "1.2"

    def run(self):
        if ("memory" in self.results and
            "svcscan" in self.results["memory"]):
            for s in self.results["memory"]["svcscan"]["data"]:
                if (s["service_name"] == "wscsvc" and
                    s["service_state"] == "SERVICE_STOPPED"):
                    self.add_match(None, "stopped_service", s)

        return self.has_matches()


class VolSvcscan3(Signature):
    name = "volatility_svcscan_3"
    description = "Stopped Application Layer Gateway service"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "1.2"

    def run(self):
        if ("memory" in self.results and
            "svcscan" in self.results["memory"]):
            for s in self.results["memory"]["svcscan"]["data"]:
                if (s["service_name"] == "ALG" and
                    s["service_state"] == "SERVICE_STOPPED"):
                    self.add_match(None, "stopped_service", s)

        return self.has_matches()


class VolModscan1(Signature):
    name = "volatility_modscan_1"
    description = "Kernel module without a name"
    severity = 3
    alert = True
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    families = ["Zero access"]
    minimum = "1.2"

    def run(self):
        if ("memory" in self.results and
            "modscan" in self.results["memory"]):
            for m in self.results["memory"]["modscan"]["data"]:
                if m["kernel_module_name"] == "":
                    self.add_match(None, "mysterious_kernel_module", m)

        return self.has_matches()


class VolHandles1(Signature):
    name = "volatility_handles_1"
    description = "Lots of threads in other processes"
    severity = 2
    alert = False
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "1.2"

    def run(self):
        threads = set()

        if ("memory" in self.results and
            "handles" in self.results["memory"]):
            for h in self.results["memory"]["handles"]["data"]:
                if h["handle_type"] == "Thread":
                    w1, t1, w2, p1 = h["handle_name"].split(" ")
                    t1 = int(t1)
                    p1 = int(p1)
                    if p1 != h["process_id"]:
                        threads.add("%d -> %d/%d" % (h["process_id"], p1, t1))

        if len(threads) > 5:
            self.data.append({"injections": list(threads)})
            self.add_match(None, "injections", list(threads))
            return True

        return False
