# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import os
import hashlib
import re
import traceback
import pprint

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
from maec40_mappings import api_call_mappings, hiveHexToString

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.utils import datetime_to_iso


class MAEC40Report(Report):
    """Generates a MAEC 4.0 report.
       Output modes:
       mode = "full" : Output fully mapped Actions along with Action Implementations
       mode = "overview" : Output only fully mapped Actions with no Action Implementations
       mode = "api" : Output only Actions with Action Implementations, but no mapped components
    """

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
        if ":" in network_data.get("src", ""): src_category = "ipv6-addr"
        if ":" in network_data.get("dst", ""): dst_category = "ipv6-addr"
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

    def apiCallToAction(self, call, pos):
        """Create and return a dictionary representing a MAEC Malware Action.
        @param call: the input API call.
        @param pos: position of the Action with respect to the execution of the malware.
        """ 
        # Setup the action/action implementation dictionaries and lists
        action_dict = {}
        parameter_list = []
        # Add the action parameter arguments
        apos = 1
        for arg in call["arguments"]:
            parameter_list.append({"ordinal_position" : apos,
                                   "name" : arg["name"],
                                   "value" : self._illegal_xml_chars_RE.sub("?", arg["value"])
                                        })
            apos = apos + 1
        # Try to add the mapped Action Name
        if call["api"] in api_call_mappings:
            mapping_dict = api_call_mappings[call["api"]]
            # Handle the Action Name
            if "action_vocab" in mapping_dict:
                action_dict["name"] = {"value" : mapping_dict["action_name"], "xsi:type" : mapping_dict["action_vocab"]}
            else:
                action_dict["name"] = {"value" : mapping_dict["action_name"]}
        # Try to add the mapped Action Arguments and Associated Objects
        # Only output in "overview" or "full" modes 
        if self.options["mode"].lower() == "overview" or self.options["mode"].lower() == "full":
            # Check to make sure we have a mapping for this API call
            if call["api"] in api_call_mappings:
                mapping_dict = api_call_mappings[call["api"]]
                # Handle the Action Name
                if "action_vocab" in mapping_dict:
                    action_dict["name"] = {"value" : mapping_dict["action_name"], "xsi:type" : mapping_dict["action_vocab"]}
                else:
                    action_dict["name"] = {"value" : mapping_dict["action_name"]}
                # Handle any Parameters
                if "parameter_associated_arguments" in mapping_dict:
                    action_dict["action_arguments"] = self.processActionArguments(mapping_dict["parameter_associated_arguments"], parameter_list)
                # Handle any Associated Objects
                if "parameter_associated_objects" in mapping_dict:
                    action_dict["associated_objects"] = self.processActionAssociatedObjects(mapping_dict["parameter_associated_objects"], parameter_list)

        # Only output Implementation in "api" or "full" modes
        if self.options["mode"].lower() == "api" or self.options["mode"].lower() == "full":
            action_dict["implementation"] = self.processActionImplementation(call, parameter_list)

        # Add the common Action properties
        action_dict["id"] = self.id_generator.generate_malware_action_id()
        action_dict["ordinal_position"] = pos
        action_dict["action_status"] = self.mapActionStatus(call["status"])
        action_dict["timestamp"] = str(call["timestamp"]).replace(" ", "T").replace(",",".")

        return action_dict

    def processActionImplementation(self, call, parameter_list):
        """Creates a MAEC Action Implementation based on API call input.
        @param parameter_list: the input parameter list (from the API call).
        """
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
                                        "api_call" : api_call_dict}
        return action_implementation_dict
                      
    def processActionArguments(self, parameter_mappings_dict, parameter_list):
        """Processes a dictionary of parameters that should be mapped to Action Arguments in the Malware Action.
        @param parameter_mappings_dict: the input parameter to Arguments mappings.
        @param parameter_list: the input parameter list (from the API call).
        """  
        arguments_list = []
        for call_parameter in parameter_list:
            parameter_name = call_parameter["name"]
            if parameter_name in parameter_mappings_dict and "associated_argument_vocab" in parameter_mappings_dict[parameter_name]:
                arguments_list.append({"argument_value" : call_parameter["value"], 
                                        "argument_name" : {"value" : parameter_mappings_dict[parameter_name]["associated_argument_name"],
                                                            "xsi:type" : parameter_mappings_dict[parameter_name]["associated_argument_vocab"]}})
            elif parameter_name in parameter_mappings_dict and "associated_argument_vocab" not in parameter_mappings_dict[parameter_name]:
                arguments_list.append({"argument_value" : call_parameter["value"], 
                                        "argument_name" : {"value" : parameter_mappings_dict[parameter_name]["associated_argument_name"]}})
        return arguments_list

    def processActionAssociatedObjects(self, associated_objects_dict, parameter_list):
        """Processes a dictionary of parameters that should be mapped to Associated Objects in the Action
        @param associated_objects_dict: the input parameter to Associated_Objects mappings.
        @param parameter_list: the input parameter list (from the API call).
        """ 
        associated_objects_list = []
        processed_parameters = []
        # First, handle any parameters that need to be grouped together into a single Object
        if "group_together" in associated_objects_dict:
            grouped_list = associated_objects_dict["group_together"]
            associated_object_dict = {}
            associated_object_dict["id"] = self.id_generator.generate_object_id()
            associated_object_dict["properties"] = {}
            for parameter_name in grouped_list:
                self.processAssociatedObject(associated_objects_dict[parameter_name], self.getParameterValue(parameter_list, parameter_name), associated_object_dict)
                # Add the parameter to the list of those that have already been processed
                processed_parameters.append(parameter_name)
            associated_objects_list.append(associated_object_dict)
        # Handle grouped nested parameters (corner case)
        if "group_together_nested" in associated_objects_dict:
            nested_group_dict = associated_objects_dict["group_together_nested"]
            # Construct the values dictionary
            values_dict = {}
            for parameter_mapping in nested_group_dict["parameter_mappings"]:
                values_dict[parameter_mapping["element_name"].lower()] = self.getParameterValue(parameter_list, parameter_mapping["parameter_name"])
            associated_objects_list.append(self.processAssociatedObject(nested_group_dict, values_dict))
        # Handle non-grouped, normal parameters
        for call_parameter in parameter_list:
            if call_parameter["name"] not in processed_parameters and call_parameter["name"] in associated_objects_dict:
                associated_objects_list.append(self.processAssociatedObject(associated_objects_dict[call_parameter["name"]], self.getParameterValue(parameter_list, call_parameter["name"])))
        return associated_objects_list

    
    def processAssociatedObject(self, parameter_mapping_dict, parameter_value, associated_object_dict = None):
        """Process a single Associated Object mapping.
        @param parameter_mapping_dict: input parameter to Associated Object mapping dictionary.
        @param parameter_value: the input parameter value (from the API call).
        @param associated_object_dict: optional associated object dict, for special cases.
        """
        if not associated_object_dict:   
            associated_object_dict = {}
            associated_object_dict["id"] = self.id_generator.generate_object_id()
            associated_object_dict["properties"] = {}
        # Set the XSI type if it has not been set already
        if "xsi:type" not in associated_object_dict["properties"]: 
            associated_object_dict["properties"]["xsi:type"] = parameter_mapping_dict["associated_object_type"]
        # Set the Association Type if it has not been set already
        if "association_type" not in associated_object_dict: 
            associated_object_dict["association_type"] = {"value" : parameter_mapping_dict["association_type"], "xsi:type" : "maecVocabs:ActionObjectAssociationTypeVocab-1.0"}
        # Handle any values that require post-processing (via external functions)
        if "post_processing" in parameter_mapping_dict:
            parameter_value = globals()[parameter_mapping_dict["post_processing"]](parameter_value)
        # Handle the actual element value
        if parameter_mapping_dict["associated_object_element"]:
            # Handle simple (non-nested) elements
            if "/" not in parameter_mapping_dict["associated_object_element"]:
                associated_object_dict["properties"][parameter_mapping_dict["associated_object_element"].lower()] = parameter_value
            # Handle complex (nested) elements
            elif "/" in parameter_mapping_dict["associated_object_element"]:
                split_elements = parameter_mapping_dict["associated_object_element"].split("/")
                associated_object_dict["properties"][split_elements[0].lower()] = self.createNestedDict(split_elements[1:], parameter_value)
        return associated_object_dict

    def createNestedDict(self, list, value):
        """Helper function: returns a nested dictionary for an input list.
        @param list: input list.
        @param value: value to set the last embedded dictionary item to.
        """   
        nested_dict = {}

        if len(list) == 1:
            if 'list__' in list[0]:
                if isinstance(value, dict):
                    list_element = [value]
                else:
                    list_element = [{list[0].lstrip('list__').lower() : value}]
                return list_element
            else:
                nested_dict[list[0].lower()] = value
                return nested_dict

        for list_item in list:
            next_index = list.index(list_item) + 1
            nested_dict[list_item.lower()] = self.createNestedDict(list[next_index:], value)
            break

        return nested_dict
    
    def getParameterValue(self, parameter_list, parameter_name):
        """Finds and returns an API call parameter value from a list.
        @param parameter_list: list of API call parameters.
        @param parameter_name: name of parameter to return value for.
        """                
        for parameter_dict in parameter_list:
            if parameter_dict["name"] == parameter_name:
                return parameter_dict["value"]

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

            # Generate the Action dictionary
            action_dict = self.apiCallToAction(call, pos)

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

        # A mapping of Cuckoo resource type names to their name in MAEC
        resource_type_mappings = {"GIF" : "Bitmap",
                                  "RT_ACCELERATOR" : "Accelerators",
                                  "RT_ANICURSOR" : "AniCursor",
                                  "RT_ANIICON" : "AniIcon",
                                  "RT_BITMAP" : "Bitmap",
                                  "RT_CURSOR" : "Cursor",
                                  "RT_DIALOG" : "Dialog",
                                  "RT_DLGINCLUDE" : "DLGInclude",
                                  "RT_FONT" : "Font",
                                  "RT_FONTDIR" : "Fontdir",
                                  "RT_GROUP_CURSOR" : "GroupCursor",
                                  "RT_GROUP_ICON" : "GroupIcon",
                                  "RT_HTML" : "HTML",
                                  "RT_ICON" : "Icon",
                                  "RT_MANIFEST" : "Manifest",
                                  "RT_MENU" : "Menu",
                                  "RT_PLUGPLAY" : "PlugPlay",
                                  "RT_RCDATA" : "RCData",
                                  "RT_STRING" : "String",
                                  "RT_VERSION" : "VersionInfo",
                                  "RT_VXD" : "Vxd"}

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
                    if r["name"] in resource_type_mappings:
                        resource_dict = {"type" : resource_type_mappings[r["name"]]}
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
        """Add Malware Instance Object Attributes to the Malware Subject."""
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
            report.flush()
            report.close()
        except (TypeError, IOError) as e:
            traceback.print_exc()
            raise CuckooReportError("Failed to generate MAEC 4.0 report: %s" % e)
            
            
