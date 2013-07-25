# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import os
import hashlib
import re

from cybox.core import Object
from cybox.common import ToolInformation
from cybox.common import StructuredText
from maec.bundle.bundle import Bundle
from maec.bundle.malware_action import MalwareAction
from maec.bundle.bundle_reference import BundleReference
from maec.bundle.process_tree import ProcessTree
from maec.bundle.av_classification import AVClassification
from maec.id_generator import Generator
from maec.package.malware_subject import MalwareSubject
from maec.package.package import Package
from maec.package.analysis import Analysis
from maec.utils import MAECNamespaceParser

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.utils import datetime_to_iso


class MAEC40Report(Report):
    """Generates a MAEC 4.0 report."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        self._illegal_xml_chars_RE = re.compile(u'[\x00-\x08\x0b\x0c\x0e-\x1F\uD800-\uDFFF\uFFFE\uFFFF]')
        # Map of PIDs to the Actions that they spawned
        self.pidActionMap = {}
        # Save results
        self.results = results
        # Setup MAEC document structure
        self.setupMAEC()
        # Build MAEC doc
        self.addSubjectAttributes()
        self.addDroppedFiles()
        self.addAnalyses()
        self.addActions()
        self.addProcessTree()
        # Write XML report
        self.output() 

    def setupMAEC(self):
        """Generates MAEC Package, Malware Subject, and Bundle structure"""
        if self.results["target"]["category"] == "file":
            self.id_generator = Generator(self.results["target"]["file"]["md5"])
        elif self.results["target"]["category"] == "url":
            self.id_generator = Generator(hashlib.md5(self.results["target"]["url"]).hexdigest())
        else:
            raise CuckooReportError("Unknown target type")

        # Generate Package
        self.package = Package(self.id_generator.generate_package_id())
        # Generate Malware Subject
        self.subject = MalwareSubject(self.id_generator.generate_malware_subject_id())
        # Add the Subject to the Package
        self.package.add_malware_subject(self.subject)
        # Generate dynamic analysis bundle
        self.dynamic_bundle = Bundle(self.id_generator.generate_bundle_id(), False, 4.0, "dynamic analysis tool output")
        # Add the Bundle to the Subject
        self.subject.add_findings_bundle(self.dynamic_bundle)
        # Generate Static Analysis Bundles, if static results exist
        if "static" in self.results and self.results["static"]:
            self.static_bundle = Bundle(self.id_generator.generate_bundle_id(), False, 4.0, "static analysis tool output")
            self.subject.add_findings_bundle(self.static_bundle) 
        if "strings" in self.results and self.results["strings"]:
            self.strings_bundle = Bundle(self.id_generator.generate_bundle_id(), False, 4.0, "static analysis tool output")
            self.subject.add_findings_bundle(self.strings_bundle)
        if "virustotal" in self.results and self.results["virustotal"]:
            self.virustotal_bundle = Bundle(self.id_generator.generate_bundle_id(), False, 4.0, "static analysis tool output")
            self.subject.add_findings_bundle(self.virustotal_bundle) 

    def addActions(self):
        """Add Actions section."""
        # Process-initiated Actions
        for process in self.results["behavior"]["processes"]:
            self.createProcessActions(process)
        # Network actions
        if "network" in self.results and isinstance(self.results["network"], dict) and len(self.results["network"]) > 0:
            if "udp" in self.results["network"] and isinstance(self.results["network"]["udp"], list) and len(self.results["network"]["udp"]) > 0:
                if not self.dynamic_bundle.collections.action_collections.has_collection("Network Actions"):
                    self.dynamic_bundle.add_named_action_collection("Network Actions", self.id_generator.generate_action_collection_id())
                for network_data in self.results["network"]["udp"]:
                    self.createActionNet(network_data, {"value" : "connect to socket address", "xsi:type" : "maecVocabs:NetworkActionNameVocab-1.0"}, "UDP")
            if "dns" in self.results["network"] and isinstance(self.results["network"]["dns"], list) and len(self.results["network"]["dns"]) > 0:
                if not self.dynamic_bundle.collections.action_collections.has_collection("Network Actions"):
                    self.dynamic_bundle.add_named_action_collection("Network Actions", self.id_generator.generate_action_collection_id())
                for network_data in self.results["network"]["dns"]:
                    self.createActionNet(network_data, {"value" : "send dns query", "xsi:type" : "maecVocabs:DNSActionNameVocab-1.0"}, "UDP", "DNS")
            if "tcp" in self.results["network"] and isinstance(self.results["network"]["tcp"], list) and len(self.results["network"]["tcp"]) > 0:
                if not self.dynamic_bundle.collections.action_collections.has_collection("Network Actions"):
                    self.dynamic_bundle.add_named_action_collection("Network Actions", self.id_generator.generate_action_collection_id())
                for network_data in self.results["network"]["tcp"]:
                    self.createActionNet(network_data, {"value" : "connect to socket address", "xsi:type" : "maecVocabs:NetworkActionNameVocab-1.0"}, "TCP")
            if "http" in self.results["network"] and isinstance(self.results["network"]["http"], list) and len(self.results["network"]["http"]) > 0:
                if not self.dynamic_bundle.collections.action_collections.has_collection("Network Actions"):
                    self.dynamic_bundle.add_named_action_collection("Network Actions", self.id_generator.generate_action_collection_id())
                for network_data in self.results["network"]["http"]:
                    self.createActionNet(network_data, {"value" : "send http " + str(network_data["method"]).lower() + " request", "xsi:type" : "maecVocabs:HTTPActionNameVocab-1.0"}, "TCP", "HTTP")

    def createActionNet(self, network_data, action_name, layer4_protocol = None, layer7_protocol = None):
        """Create a network Action.
        @return: action.
        """
        src_category = "ipv4-addr"
        dst_category = "ipv4-addr"
        if ":" in network_data.get('src', ""): src_category = "ipv6-addr"
        if ":" in network_data.get('dst', ""): dst_category = "ipv6-addr"
        # Construct the various dictionaries
        if layer7_protocol is not None:
            object_properties = {"xsi:type" : "NetworkConnectionObjectType",
                                 "layer4_protocol" : {"value" : layer4_protocol, "force_datatype" : True},
                                 "layer7_protocol" : {"value" : layer7_protocol, "force_datatype" : True}}
        else:
            object_properties = {"xsi:type" : "NetworkConnectionObjectType",
                                 "layer4_protocol" : {"value" : layer4_protocol, "force_datatype" : True}}
        associated_object = {"id" : self.id_generator.generate_object_id(), "properties": object_properties}
        # General network connection properties
        if layer7_protocol == None:
            object_properties["source_socket_address"] = {"ip_address" : {"category" : src_category, "address_value" : network_data["src"]},
                                                          "port" : {"port_value" : network_data["sport"]}}
            object_properties["destination_socket_address"] = {"ip_address" : {"category" : dst_category, "address_value" : network_data["dst"]},
                                                          "port" : {"port_value" : network_data["dport"]}}
        # Layer 7-specific object properties
        if layer7_protocol == "DNS":
            answer_resource_records = []
            for answer_record in network_data["answers"]:
                answer_resource_records.append({"entity_type" : answer_record["type"], 
                                                "record_data" : answer_record["data"]})
            object_properties["layer7_connections"] = {"dns_queries" : [{"question" : {"qname" : {"value" : network_data["request"]},
                                                                                       "qtype" : network_data["type"]},
                                                                         "answer_resource_records" : answer_resource_records}]}
        elif layer7_protocol == "HTTP":
            object_properties["layer7_connections"] = {"http_session" : 
                                                       {"http_request_responses" : [{"http_client_request": {"http_request_line" : {"http_method" : network_data["method"],
                                                                                                                                    "value" : network_data["path"],
                                                                                                                                    "version" : network_data["version"]},
                                                                                                             "http_request_header" : {"parsed_header" : {"user_agent" : network_data["user-agent"],
                                                                                                                                                         "host" : {"domain_name" : {"value" : network_data["host"]},
                                                                                                                                                                   "port" : {"port_value" : network_data["port"]}}}},
                                                                                                             "http_message_body" : {"message_body" : network_data["body"]}}
                                                                                     }
                                                                                    ]}
                                                       }
        action_dict = {"id" : self.id_generator.generate_malware_action_id(),
                       "context" : "Network",
                       "name" : action_name,
                       "associated_objects" : [associated_object]}
        # Add the Action to the dynamic analysis bundle
        self.dynamic_bundle.add_action(MalwareAction.from_dict(action_dict), "Network Actions")

    def addProcessTree(self):
        """Creates the ProcessTree corresponding to that observed by cuckoo.
        """
        if "behavior" in self.results and "processtree" in self.results["behavior"]:
            root_node = self.results["behavior"]["processtree"][0]
            if root_node:
                root_node_dict = {"pid" : root_node["pid"],
                                    "name" : root_node["name"],
                                    "initiated_actions" : self.pidActionMap[root_node["pid"]],
                                    "spawned_processes" : [self.createProcessTreeNode(child_process) for child_process in root_node["children"]]
                                    }
                self.dynamic_bundle.set_process_tree(ProcessTree.from_dict(root_node_dict))

    def createProcessTreeNode(self, process):
        """Creates a single ProcessTreeNode corresponding to a single node in the tree observed cuckoo.
        @param process: process from cuckoo dict.
        """
        process_node_dict = {"pid" : process["pid"],
                            "name" : process["name"],
                            "initiated_actions" : self.pidActionMap[process["pid"]],
                            "spawned_processes" : [self.createProcessTreeNode(child_process) for child_process in process["children"]]
                            }
        return process_node_dict

    def createProcessActions(self, process):
        """Creates the Actions corresponding to the API calls initiated by a process.
        @param process: process from cuckoo dict.
        """
        pos = 1
        pid = process["process_id"]

        for call in process["calls"]:
            # Generate the action collection name and create a new named action collection if one does not exist
            action_collection_name = str(call["category"]).capitalize() + " Actions"
            if not self.dynamic_bundle.collections.action_collections.has_collection(action_collection_name):
                self.dynamic_bundle.add_named_action_collection(action_collection_name, self.id_generator.generate_action_collection_id())
            # Setup the action/action implementation dictionaries and lists
            parameter_list = []
            # Add the action parameter arguments
            apos = 1
            for arg in call["arguments"]:
                parameter_list.append({"ordinal_position" : apos,
                                         "name" : arg["name"],
                                         "value" : self._illegal_xml_chars_RE.sub("?", arg["value"])
                                         })
                apos = apos + 1
            # Generate the API Call dictionary
            if len(parameter_list) > 0:
                api_call_dict = {"function_name" : call["api"],
                                 "return_value" : call["return"],
                                 "parameters" : parameter_list}
            else:
                api_call_dict = {"function_name" : call["api"],
                                 "return_value" : call["return"]}
            # Generate the action implementation dictionary
            action_implementation_dict = {"id" : self.id_generator.generate_action_implementation_id(),
                                          "type" : "api call",
                                          "api_call" : {"function_name" : call["api"],
                                                        "return_value" : call["return"],
                                                        "parameters" : parameter_list
                                                        }
                                          }
            # Generate the action dictionary
            action_dict = {"id" : self.id_generator.generate_malware_action_id(),
                           "ordinal_position" : pos,
                           "action_status" : self.mapActionStatus(call["status"]),
                           "context" : "Host",
                           "timestamp" : str(call["timestamp"]).replace(" ", "T").replace(",","."), 
                           "implementation" : action_implementation_dict}

            # Add the action ID to the list of Actions spawned by the process
            if pid in self.pidActionMap:
                action_list = self.pidActionMap[pid].append({'action_id' : action_dict['id']})
            else:
                self.pidActionMap[pid] = [{'action_id' : action_dict['id']}]

            # Add the action to the dynamic analysis Bundle
            self.dynamic_bundle.add_action(MalwareAction.from_dict(action_dict), action_collection_name)
            # Update the action position
            pos = pos + 1
            
    # Map the Cuckoo status to that used in the MAEC/CybOX action_status field
    def mapActionStatus(self, status):
        if status == True or status == 1:
            return "Success"
        elif status == False or status == 0:
            return "Fail"
        else:
            return None

    def createWinExecFileObj(self):
        """Creates a Windows Executable File (PE) object for capturing static analysis output.
        """
        if len(self.results["static"]) > 0:
            exports = {}
            imports = []
            sections = []
            resources = []
            version_info = {}

            object_dict = {"id" : self.id_generator.generate_object_id(),
                           "properties" : {"xsi:type":"WindowsExecutableFileObjectType",
                                            "imports" : imports,
                                            "exports" : exports,
                                            "sections" : sections,
                                            "resources" : resources
                                            }
                            }
            # PE exports
            if len(self.results["static"]["pe_exports"]) > 0:
                exported_function_list = []
                for x in self.results["static"]["pe_exports"]:
                    exported_function_dict = {
                                                "function_name" : x["name"],
                                                "ordinal" : x["ordinal"],
                                                "entry_point" : x["address"]
                                                }
                    exported_function_list.append(exported_function_dict)
                exports['exported_functions'] = exported_function_list
            # PE Imports
            if len(self.results["static"]["pe_imports"]) > 0:
                for x in self.results["static"]["pe_imports"]:
                    imported_functions = []
                    import_dict = { "file_name" : x["dll"],
                                    "imported_functions" : imported_functions}
                                                
                    # Imported functions
                    for i in x["imports"]:
                        imported_function_dict = { "function_name" : i["name"],
                                                    "virtual_address" : i["address"]}
                        imported_functions.append(imported_function_dict)
                    imports.append(import_dict)
            # Resources
            if len(self.results["static"]["pe_resources"]) > 0:
                for r in self.results["static"]["pe_resources"]:
                    resource_dict = {"name" : r["name"]}
                    resources.append(resource_dict)
            # Sections
            if len(self.results["static"]["pe_sections"]) > 0:
                for s in self.results["static"]["pe_sections"]:
                    section_dict = {"section_header" : 
                                    {"virtual_size" : int(s["virtual_size"], 16),
                                        "virtual_address" : s["virtual_address"],
                                        "name" : s["name"],
                                        "size_of_raw_data" : s["size_of_data"]
                                        },
                                    "entropy" : {"value" : s["entropy"]}
                                    }
                    sections.append(section_dict)
            # Version info
            if len(self.results["static"]["pe_versioninfo"]) > 0:
                for k in self.results["static"]["pe_versioninfo"]:
                    if k["name"].lower() == "comments" and len(k["value"]) > 0:
                        version_info["comments"] = k["value"]
                    if k["name"].lower() == "companyname" and len(k["value"]) > 0:
                        version_info["companyname"] = k["value"]
                    if k["name"].lower() == "productversion" and len(k["value"]) > 0:
                        version_info["productversion"] = k["value"]
                    if k["name"].lower() == "productname" and len(k["value"]) > 0:
                        version_info["product_name"] = k["value"]
                    if k["name"].lower() == "filedescription" and len(k["value"]) > 0:
                        version_info["filedescription"] = k["value"]
                    if k["name"].lower() == "fileversion" and len(k["value"]) > 0:
                        version_info["fileversion"] = k["value"]
                    if k["name"].lower() == "internalname" and len(k["value"]) > 0:
                        version_info["internalname"] = k["value"]
                    if k["name"].lower() == "langid" and len(k["value"]) > 0:
                        version_info["langid"] = k["value"]
                    if k["name"].lower() == "legalcopyright" and len(k["value"]) > 0:
                        version_info["legalcopyright"] = k["value"]
                    if k["name"].lower() == "legaltrademarks" and len(k["value"]) > 0:
                        version_info["legaltrademarks"] = k["value"]
                    if k["name"].lower() == "originalfilename" and len(k["value"]) > 0:
                        version_info["originalfilename"] = k["value"]
                    if k["name"].lower() == "privatebuild" and len(k["value"]) > 0:
                        version_info["privatebuild"] = k["value"]
                    if k["name"].lower() == "productname" and len(k["value"]) > 0:
                        version_info["productname"] = k["value"]
                    if k["name"].lower() == "productversion" and len(k["value"]) > 0:
                        version_info["productversion"] = k["value"]
                    if k["name"].lower() == "specialbuild" and len(k["value"]) > 0:
                        version_info["specialbuild"] = k["value"]
                resources.append(version_info)
        win_exec_file_obj = Object.from_dict(object_dict)
        return win_exec_file_obj
        
    def createFileStringsObj(self):
        """Creates a File object for capturing strings output."""
        extracted_string_list = []
        for extracted_string in self.results["strings"]:
            extracted_string_list.append({"string_value" : self._illegal_xml_chars_RE.sub("?", extracted_string)})
        extracted_features = {"strings" : extracted_string_list}
        object_dict = {"id" : self.id_generator.generate_object_id(),
                        "properties" : {"xsi:type":"FileObjectType",
                                        "extracted_features" : extracted_features
                                        }
                        }
        strings_file_obj = Object.from_dict(object_dict)
        return strings_file_obj
        
    def createFileObj(self, file):
        """Creates a File object.
        @param file: file dict from Cuckoo dict.
        @requires: file object.
        """
        if "ssdeep" in file and file["ssdeep"] is not None:
            hashes_list = [{"type" : "MD5", "simple_hash_value" : file["md5"]},
                      {"type" : "SHA1", "simple_hash_value" : file["sha1"]},
                      {"type" : "SHA256", "simple_hash_value" : file["sha256"]},
                      {"type" : "SHA512", "simple_hash_value" : file["sha512"]},
                      {"type" : "SSDEEP", "fuzzy_hash_value" : file["ssdeep"]}]
        else:
            hashes_list = [{"type" : "MD5", "simple_hash_value" : file["md5"]},
                      {"type" : "SHA1", "simple_hash_value" : file["sha1"]},
                      {"type" : "SHA256", "simple_hash_value" : file["sha256"]},
                      {"type" : "SHA512", "simple_hash_value" : file["sha512"]}]
        object_dict = {"id" : self.id_generator.generate_object_id(),
                        "properties" : {"xsi:type":"FileObjectType",
                                        "file_name" : file["name"],
                                        "file_path" : {"value" : file["path"]},
                                        "file_format" : file["type"],
                                        "size_in_bytes" : file["size"],
                                        "hashes" : hashes_list}
                        }
        file_obj = Object.from_dict(object_dict)
        return file_obj

    def addSubjectAttributes(self):
        # Add subject
        # File Object
        if self.results["target"]["category"] == "file":
            self.subject.set_malware_instance_object_attributes(self.createFileObj(self.results["target"]["file"]))
        # URL Object
        elif self.results["target"]["category"] == "url":
            url_object_dict = {"id" : self.id_generator.generate_object_id(), "properties" :  {"xsi:type" : "URIObjectType", "value" : self.results["target"]["url"]}}
            self.subject.set_malware_instance_object_attributes(Object.from_dict(url_object_dict))

    def addAnalyses(self):
        """Adds analysis header."""
        # Add the dynamic analysis
        dynamic_analysis = Analysis(self.id_generator.generate_analysis_id(), "dynamic", "triage", BundleReference.from_dict({'bundle_idref' : self.dynamic_bundle.id}))
        dynamic_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
        dynamic_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
        dynamic_analysis.summary = StructuredText("Cuckoo Sandbox dynamic analysis of the malware instance object.")
        dynamic_analysis.add_tool(ToolInformation.from_dict({"id" : self.id_generator.generate_tool_id(),
                                                             "name" : "Cuckoo Sandbox",
                                                             "version" : self.results["info"]["version"],
                                                             "vendor" : "http://www.cuckoosandbox.org"}))
        self.subject.add_analysis(dynamic_analysis)

        # Add the static analysis
        if self.results["static"]:
            static_analysis = Analysis(self.id_generator.generate_analysis_id(), "static", "triage", BundleReference.from_dict({"bundle_idref" : self.static_bundle.id}))
            static_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
            static_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
            static_analysis.summary = StructuredText("Cuckoo Sandbox static (PE) analysis of the malware instance object.")
            static_analysis.add_tool(ToolInformation.from_dict({"id" : self.id_generator.generate_tool_id(),
                                                                "name" : "Cuckoo Sandbox Static Analysis",
                                                                "version" : self.results["info"]["version"],
                                                                "vendor" : "http://www.cuckoosandbox.org"}))
            self.subject.add_analysis(static_analysis)
            # Add the static file results
            self.static_bundle.add_object(self.createWinExecFileObj())
        # Add the strings analysis
        if self.results["strings"]:
            strings_analysis = Analysis(self.id_generator.generate_analysis_id(), "static", "triage", BundleReference.from_dict({"bundle_idref" : self.strings_bundle.id}))
            strings_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
            strings_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
            strings_analysis.summary = StructuredText("Cuckoo Sandbox strings analysis of the malware instance object.")
            strings_analysis.add_tool(ToolInformation.from_dict({"id" : self.id_generator.generate_tool_id(),
                                                                 "name" : "Cuckoo Sandbox Strings",
                                                                 "version" : self.results["info"]["version"],
                                                                 "vendor" : "http://www.cuckoosandbox.org"}))
            self.subject.add_analysis(strings_analysis)
            # Add the strings results
            self.strings_bundle.add_object(self.createFileStringsObj())
        # Add the VirusTotal analysis
        if "virustotal" in self.results and self.results["virustotal"]:
            virustotal_analysis = Analysis(self.id_generator.generate_analysis_id(), "static", "triage", BundleReference.from_dict({"bundle_idref" : self.strings_bundle.id}))
            virustotal_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
            virustotal_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
            virustotal_analysis.summary = StructuredText("Virustotal results for the malware instance object.")
            virustotal_analysis.add_tool(ToolInformation.from_dict({"id" : self.id_generator.generate_tool_id(),
                                                                    "name" : "VirusTotal",
                                                                    "vendor" : "https://www.virustotal.com/"}))
            self.subject.add_analysis(virustotal_analysis)
            # Add the VirusTotal results
            for engine, signature in self.results["virustotal"]["scans"].items():
                if signature['detected']:
                    self.virustotal_bundle.add_av_classification(AVClassification.from_dict({"vendor" : engine,
                                                                                             "engine_version" : signature["version"],
                                                                                             "definition_version" : signature["update"],
                                                                                             "classification_name" : signature["result"]}))
        
    def addDroppedFiles(self):
        """Adds Dropped files as Objects."""
        objs = self.results["dropped"]
        if self.results["target"]["category"] == "file":
            objs.append(self.results["target"]["file"])
        # Add the named object collection
        self.dynamic_bundle.add_named_object_collection("Dropped Files", self.id_generator.generate_object_collection_id())
        for file in objs:
            self.dynamic_bundle.add_object(self.createFileObj(file), "Dropped Files")
            
    def output(self):
        """Writes report to disk."""
        try:
            report = open(os.path.join(self.reports_path, "report.maec-4.0.xml"), "w")
            report.write("<?xml version='1.0' encoding='UTF-8'?>\n")
            report.write("<!DOCTYPE doc [<!ENTITY comma '&#44;'>]>\n")
            report.write("<!--\n")
            report.write("Cuckoo Sandbox MAEC 4.0 malware analysis report\n")
            report.write("http://www.cuckoosandbox.org\n")
            report.write("-->\n")
            self.package.to_obj().export(report, 0, name_="MAEC_Package", namespacedef_=MAECNamespaceParser(self.package.to_obj()).get_namespace_schemalocation_str())
            report.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate MAEC 4.0 report: %s" % e)
            
