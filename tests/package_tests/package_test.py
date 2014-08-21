import unittest
import json 
import os

class TestPackage(object):
    report = {}

    # values to look for in results
    # if changed, must also need to be changed in exploits
    host_ip = "192.168.56.1"
    http_port = "8089"
    exe_http_path = "/tests/test_samples/dl.exe"

    # collect and verify loaded DLLs via LdrLoadDLL in report
    def check_loaded_dlls(self, report, dlls):
        dlls_loaded = []
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "system" and (c["api"] == "LdrLoadDll" or c["api"] == "LdrGetDllHandle"):
                    for a in c["arguments"]:
                        if a["name"] == "FileName":
                            dlls_loaded.append(a["value"])
        for d in dlls:              
            self.assertTrue(d in dlls_loaded, "DLL %s not loaded" %(d))

    # check if files have been created
    def check_files(self, report, files):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "filesystem" and c["api"] == "NtCreateFile":
                    for a in c["arguments"]:
                        if a["name"]=="FileName":
                            try:
                                fname = a["value"].split("\\")
                                files.remove(fname[len(fname)-1:][0])
                            except:
                                pass

        self.assertFalse(files, "Files have note been written: %s" %(files))

    # check for dropped files
    def check_dropped_files(self, report, files):
        for d in report["dropped"]:
            try:
                files.remove(d["name"])
            except:
                pass

        self.assertFalse(files, "Files have note been seen as dropped: %s" %(files))

    # verify dns requests in report
    def check_dns_requests(self, report, hosts):
        host_lookups = []
        addr_infos = []
        for p in report["network"]["dns"]:
            host_lookups.append(p["request"])

        for d in hosts:                    
            self.assertTrue(d in host_lookups, "Host %s not listed in DNS requests" %(d))


    # check for network connections in report
    def check_network(self, report, network_items):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "network":
                    for a in c["arguments"]:
                        try:
                            if(c["api"]=="InternetReadFile"):
                                network_items.remove({"InternetReadFile":{}})
                            else:
                                network_items.remove({c["api"]:{a["name"]:a["value"]}})
                        except:
                            pass
        self.assertFalse(network_items, "Not all network items found. Not found: %s" %(network_items))

    # check for network connections in report
    def check_socket(self, report, socket_items):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "socket":
                    for a in c["arguments"]:
                        try:
                            socket_items.remove({c["api"]:{a["name"]:a["value"]}})
                        except:
                            pass
        self.assertFalse(socket_items, "Not all socket items found. Not found: %s" %(socket_items))

    # check for network connections in report
    def check_http(self, report, urls):
        for h in report["network"]["http"]:
            try: 
                urls.remove(h["uri"])
            except: 
                pass
        self.assertFalse(urls, "Not all URLs found. Not found: %s" %(urls))


    # verify registry changes/queries in report
    def check_registry(self, report, reg_items, reg_keys):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "registry":
                    for a in c["arguments"]:
                        try:
                            if(c["api"]=="NtDeleteKey"):
                                reg_items.remove({"NtDeleteKey":{}})
                            else :
                                reg_items.remove({c["api"]:{a["name"]:a["value"]}})
                        except:
                            pass

        self.assertFalse(reg_items, "Not all registry items found. Not found: %s" %(reg_items))

        # check for complete regkey list
        self.assertTrue(report.get("behavior").get("summary").get("keys"), "No Registry Keys found at all")
        for r in reg_keys:
            self.assertTrue(r in report["behavior"]["summary"]["keys"], "Key not listed: %s" %(r))

    def check_processes(self, report, proc_list): 
        for p in report["behavior"]["processes"]:
            try:
                proc_list.remove(p["process_name"])
            except:
                pass
        self.assertFalse(proc_list, "Not all processes found. Not found: %s" %(proc_list))

