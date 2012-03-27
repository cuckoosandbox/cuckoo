# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.    

import os

from cuckoo.reporting.observers import BaseObserver
import cuckoo.reporting.maec11 as maec
from cuckoo.reporting.utils import convertTime

class Report(BaseObserver):
    """
    Generates a MAEC report.
    """
    
    def __init__(self, analysis_path):
        BaseObserver.__init__(self, analysis_path)
        self.idMap ={}

    def update(self, results):  
        # Save results
        self.results = results
        # Build MAEC doc
        self.addBundle()
        self.addPools()
        self.addAnalysis()
        self.addActions()
        self.output()

    def addBundle(self):
        """
        Generates MAEC bundle structure.
        """
        self.idMap['prefix'] = "maec:%s" % self.results['file']['md5']

        # Generate bundle    
        self.m = maec.BundleType(
                                id = "%s:bnd:1" % self.idMap['prefix'], 
                                schema_version='1.1'
                                )
        # Analyses
        self.analyses = maec.AnalysesType()
        self.m.set_Analyses(self.analyses)
        # Actions
        self.actions = maec.ActionsType()
        self.m.set_Actions(self.actions)
        # Behaviors
        self.behaviors = maec.BehaviorsType()
        self.m.set_Behaviors(self.behaviors)
        # Pools
        self.pools = maec.PoolsType()
        self.m.set_Pools(self.pools)
        
    def getActionId(self):
        try:
            self.actionId = self.actionId +1
        except AttributeError:
            self.actionId = 1
        return self.actionId

    def getObjectId(self):
        try:
            self.objectId = self.objectId +1
        except AttributeError:
            self.objectId = 1
        return self.objectId
    
    def getProcessId(self):
        try:
            self.processId = self.processId +1
        except AttributeError:
            self.processId = 1
        return self.processId
    
    def getActImpId(self):
        try:
            self.actImpId = self.actImpId +1
        except AttributeError:
            self.actImpId = 1
        return self.actImpId
    
    def getApiCallId(self):
        try:
            self.apiCallId = self.apiCallId +1
        except AttributeError:
            self.apiCallId = 1
        return self.apiCallId
      
    def addActions(self):
        """
        Adds actions section
        """
        # Processes
        for process in self.results['behavior']['processes']:
            self.createActionAPI(process)      
        # Network
        if not self.results["network"]:
		print "No network data"
		return
        if len(self.results['network']['udp']) > 0:
            for pkt in self.results['network']['udp']:
                self.createActionNet(pkt)
        if len(self.results['network']['tcp']) > 0:
            for pkt in self.results['network']['tcp']:
                self.createActionNet(pkt)
            
    def createActionNet(self, packet):
        act = maec.ActionType(
                              id = "%s:act:%s" % (self.idMap['prefix'], self.getActionId()),
                              )
        act.set_Action_Initiator(maec.Action_InitiatorType(
                                                           type_ = 'Process',
                                                           Initiator_Object = maec.ObjectReferenceType(
                                                                                                       type_ = 'Object',
                                                                                                       object_id = self.idMap['subject']
                                                                                                       )
                                                           )
                                 )
        ai = maec.ActionImplementationType(
                                           type_ = 'Other',
                                           id = "%s:imp:%s" % (self.idMap['prefix'], self.getActImpId()),
                                           )
        net = maec.Network_Action_AttributesType(
                                                 Internal_Port = packet['sport'],
                                                 External_Port = packet['dport'],
                                                 Internal_IP_Address = packet['src'],
                                                 External_IP_Address = packet['dst']
                                                 )
        ai.set_Network_Action_Attributes(net)
        act.set_Action_Implementation(ai)
        self.actions.add_Action(act)
    
    def createActionAPI(self, process):
        """
        Creates an action object which describes a process.
        @param process: process from cuckoo dict
        """ 
        pid = self.getProcessId()
        pos = 1
        
        for call in process['calls']: 
            act = maec.ActionType(
                                  id = "%s:act:%s" % (self.idMap['prefix'], self.getActionId()),
                                  ordinal_position = pos,
                                  timestamp = call['timestamp'],
                                  successful = call['category']
                                  )
            try:
                initiator = self.idMap[process['process_name']]
            except KeyError:
                initiator = self.idMap['subject']
            act.set_Action_Initiator(maec.Action_InitiatorType(
                                                               type_ = 'Process',
                                                               Initiator_Object = maec.ObjectReferenceType(
                                                                                                           type_ = 'Object',
                                                                                                           object_id = initiator
                                                                                                           )
                                                               )
                                     )
            ai = maec.ActionImplementationType(
                                               type_ = 'API_Call',
                                               id = "%s:imp:%s" % (self.idMap['prefix'], self.getActImpId()),
                                               )
            apicall = maec.APICallType(
                                       id = "%s:api:%s" % (self.idMap['prefix'], self.getApiCallId()),
                                       apifunction_name = call['api'],
                                       ReturnValue = call['return']
                                       )  
            apos = 1
            for arg in call['arguments']:
                apicall.add_APICall_Parameter(maec.APICall_ParameterType(
                                                                         ordinal_position = apos,
                                                                         Name = arg['name'],
                                                                         Value = arg['value']
                                                                         )
                                              )
                apos = apos + 1
            ai.set_API_Call(apicall)
            
            act.set_Action_Implementation(ai)
            self.actions.add_Action(act)
            pos = pos +1
        
    def createFileObj(self, file):
        """
        Creates a File object.
        @param file: file dict from Cuckoo dict
        @requires: file object
        """
        obj = maec.ObjectType(
                              id = '%s:obj:%s' % (self.idMap['prefix'], self.getObjectId()), 
                              object_name = file['name'],
                              type_ = "File"
                              )
        self.idMap[file['name']] = obj.id
        
        fs = maec.File_System_Object_AttributesType()
        fs.set_File_Type(maec.File_TypeType(
                                            type_ = file['type']
                                            )
                         )
        # Add static analysis if file obj is analysis subject.
        if file['md5'] == self.results['file']['md5'] and len(self.results['static']) > 0:
            pe = maec.PE_Binary_AttributesType(dll_count = self.results['static']['imported_dll_count'])
            # PE exports
            if len(self.results['static']['pe_exports']) > 0:
                exports = maec.ExportsType()
                pe.set_Exports(exports)
                for x in self.results['static']['pe_exports']:
                    exp = maec.PEExportType(
                                            Function_Name = x['name'],
                                            Ordinal = x['ordinal'],
                                            Entry_Point = x['address']
                                            )
                    exports.add_Export(exp)
            # PE Imports
            if len(self.results['static']['pe_imports']) > 0:
                imports = maec.ImportsType()
                pe.set_Imports(imports)
                for x in self.results['static']['pe_imports']:
                    imp = maec.PEImportType(
                                            File_Name = x['dll']
                                            )
                    # Imported functions
                    funcs = maec.Imported_FunctionsType()
                    imp.set_Imported_Functions(funcs)
                    for i in x['imports']:
                        f = maec.Imported_FunctionType(
                                                       Function_Name = i['name'],
                                                       Virtual_Address = i['address']
                                                       )
                        funcs.add_Imported_Function(f)                      
                    imports.add_Import(imp)
            # Resources
            if len(self.results['static']['pe_resources']) > 0:
                resources = maec.ResourcesType()
                pe.set_Resources(resources)
                for r in self.results['static']['pe_resources']:
                    res = maec.PEResourceType(
                                            Name = r['name']
                                            )
                    resources.add_Resource(res)
            # Sections
            if len(self.results['static']['pe_sections']) > 0:
                sections = maec.SectionsType()
                pe.set_Sections(sections)
                for s in self.results['static']['pe_sections']:
                    sec = maec.PESectionType(
                                            Virtual_Size = int(s['virtual_size'], 16),
                                            Virtual_Address = s['virtual_address'],
                                            Entropy = s['entropy'],
                                            Section_Name = s['name']
                                            )
                    sections.add_Section(sec)
            # Version info
            if len(self.results['static']['pe_versioninfo']) > 0:
                version = maec.Version_BlockType()
                pe.set_Version_Block(version)
                for k in self.results['static']['pe_versioninfo']:
                    if k['name'] == 'ProductVersion':
                        version.set_Product_Version_Text(k['value'])
                    if k['name'] == 'ProductName':
                        version.set_Product_Name(k['value'])
                    if k['name'] == 'FileVersion':
                        version.set_File_Version_Text(k['value'])
                    if k['name'] == 'CompanyName':
                        version.set_Company_Name(k['value'])
                    if k['name'] == 'OriginalFilename':
                        version.set_Original_File_Name(k['value'])
            fs.set_File_Type_Attributes(maec.File_Type_AttributesType(pe))
        h = maec.HashesType()
        h.add_Hash(maec.HashType(
                                 type_ = 'MD5',
                                 Hash_Value = file['md5']
                                 ))
        h.add_Hash(maec.HashType(
                                 type_ = 'SHA1',
                                 Hash_Value = file['sha1']
                                 ))
        h.add_Hash(maec.HashType(
                                 type_ = 'SHA256',
                                 Hash_Value = file['sha256']
                                 ))
        h.add_Hash(maec.HashType(
                                 type_ = 'Other',
                                 other_type = 'SHA512',
                                 Hash_Value = file['sha512']
                                 ))
        h.add_Hash(maec.HashType(
                                 type_ = 'Other',
                                 other_type = 'CRC32',
                                 Hash_Value = file['crc32']
                                 ))
        h.add_Hash(maec.HashType(
                                 type_ = 'Other',
                                 other_type = 'SSDEEP',
                                 Hash_Value = file['ssdeep']
                                 ))
        fs.set_Hashes(h)
        obj.set_File_System_Object_Attributes(fs)
        obj.set_Object_Size(maec.Object_SizeType(
                                                 units = 'Bytes',
                                                 valueOf_ = file['size']
                                                 ))
        return obj
        
    def createSubject(self, file):
        """
        Create a subject entity
        @param file: file as in cuckoo dict
        @return: subject object 
        """
        subject = maec.SubjectType()
        subject.set_Object_Reference(maec.ObjectReferenceType(
                                                              type_ = 'Object',
                                                              object_id = self.idMap[file['name']]
                                                              )
                                     )
        self.idMap['subject'] = self.idMap[file['name']]
        return subject

    def createTools(self):
        """
        Creates a tools element
        @return: Tools object
        """
        tools = maec.Tools_UsedType()
        tool = maec.ToolType(
                             id = "%s:tol:1" % self.idMap['prefix'],
                             Name = 'Cucko Sandbox',
                             Version = self.results['info']['version'],
                             Organization = 'http://www.cuckoobox.org'
                             )
        tools.add_Tool(tool)
        return tools

    def addAnalysis(self):
        """
        Adds analysis header
        """
        analysis = maec.AnalysisType(
                                id = "%s:ana:1" % self.idMap['prefix'],
                                analysis_method = 'Dynamic',
                                start_datetime = convertTime(self.results["info"]["started"]),
                                complete_datetime = convertTime(self.results["info"]["ended"]),
                                lastupdate_datetime = convertTime(self.results["info"]["ended"])
                                )
        # Add tool
        analysis.set_Tools_Used(self.createTools())
        # Add subject
        analysis.add_Subject(self.createSubject(self.results['file']))
        # 
        self.analyses.add_Analysis(analysis)
        
    def addPools(self):
        """
        Adds Pools section.
        """
        objs = self.results['dropped']
        objs.append(self.results['file'])
        pool = maec.Object_PoolType()
        for file in objs:
            pool.add_Object(self.createFileObj(file))
        self.pools.set_Object_Pool(pool)
        
    def output(self):
        """         
        Writes report to disk.
        """
        try:
            report = open(os.path.join(self.report_path, "report.maec.xml"), "w")
            report.write('<?xml version="1.0" ?>\n')
            report.write('<!--\n')
            report.write('Cuckoo Sandbox MAEC malware analysis report\n')
            report.write('http://www.cuckoobox.org\n')
            report.write('-->\n')
            self.m.export(report, 0, namespace_ = '', name_ = 'MAEC_Bundle', namespacedef_ = 'xsi:schemaLocation="http://maec.mitre.org/XMLSchema/maec-core-1 file:MAEC_v1.1.xsd"')
            report.close()
        except Exception, e:
            print "Failed writing MAEC report: %s" % e
