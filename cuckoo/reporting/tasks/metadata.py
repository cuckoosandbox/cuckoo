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
    Generates a MAEC Malware Metadata Sharing report.
    """
        
    def update(self, results):    
        # Save results    
        self.results = results       
        # Reporting steps
        self.addMetadata()
        self.addObjects()
        self.addRelations()
        self.output()
        
    def addMetadata(self):              
        """
        Generates header for MAEC xml and root components.
        """   
        self.m = maec.malwareMetaData(
            version = '1.1', 
            id = "cuckoo:%s" % self.results['file']['md5'],
            author = "Cuckoo Sandbox %s" % self.results["info"]["version"],
            comment = "Report created with Cuckoo Sandbox %s automated and open source malware sandbox: http://www.cuckoobox.org" % self.results["info"]["version"],
            timestamp = convertTime(self.results["info"]["started"])
        )        
        # Objects
        self.objects = maec.objectsType()
        self.m.set_objects(self.objects)
        # Object Properties
        self.properties = maec.objectPropertiesType()
        self.m.set_objectProperties(self.properties)
        # Relationships
        self.relationships = maec.relationshipsType()
        self.m.set_relationships(self.relationships)
        
    def addObjects(self):
        """
        Adds objects elements.
        """
        # File objects
        # Subject
        self.objects.add_file(self.createFileObject(self.results['file']))
        # Dropped files
        for f in self.results['dropped']:
            found = False
            for exist in self.objects.get_file():
                if exist.get_md5() == f['md5']:
                    found = True
            if not found:        
                self.objects.add_file(self.createFileObject(f))
        # URI objects
        if self.results['network']:
            for req in self.results['network']['http']:
                found = False
                for exist in self.objects.get_uri():
                    if exist.get_id() == req['uri']:
                        found = True
                if not found:
                    self.objects.add_uri(self.createUriObject(req))
            
    def createFileObject(self, f):
        """
        Creates a file object.
        @param f: file hash representation from cuckoo dict results 
        @return: file object
        """
        file = maec.fileObject(
                               id = f['md5'], 
                               fileType = [f['type']], 
                               size = f['size'], 
                               crc32 = f['crc32'],
                               md5 = f['md5'], 
                               sha1 = f['sha1'], 
                               sha512 = f['sha512']
                               )
        file.add_extraHash(maec.extraHashType('ssdeep', f['ssdeep']))      
        # Add related filename
        prop = maec.objectProperty()
        prop.add_property(maec.property(
                                        type_= 'filename',
                                        valueOf_ = f['name']
                                        )
                          )
        prop.set_references(
                            maec.reference(
                                           valueOf_ = "file[@id='%s']" % f['md5']
                                           )
                            ) 
        self.properties.add_objectProperty(prop)
        return file

    def getRelId(self):
        """
        Generates incremental relation id.
        @return: generated id
        """
        try:
            self.relId = self.relId +1
        except AttributeError:
            self.relId = 1
        return self.relId
    
    def addRelations(self):
        """
        Adds relationships.
        """
        # Dropped files
        for file in self.results['dropped']:
            self.relationships.add_relationship(self.createRelation(
                                                                    action = 'installed',
                                                                    src = "file[@id='%s']" % self.results['file']['md5'],
                                                                    dst = "file[@id='%s']" % file['md5']
                                                                    )
                                                )
        # DNS requests
        for req in self.objects.get_uri():
            # Get IP
            for res in self.results['network']['dns']: 
                if res['hostname'] == req.get_hostname():
                    ip = res['ip']
                    # Check if obj exist
                    found = None
                    for obj in self.objects.get_ip():
                        if ip == obj.get_startAddress().get_valueOf_():
                            found = obj
                    # Create obj
                    if found is None:
                        found = self.createIpObject(ip)
                        self.objects.add_ip(found)
                    # Create relation
                    self.relationships.add_relationship(self.createRelation(
                                                                            action = 'isServerOfService', 
                                                                            src = "ip[@id='%s']" % found.id, 
                                                                            dst = "uri[@id='%s']" % req.id
                                                                            )
                                                        )
        # HTTP requests
        for req in self.results['network']['http']:
            self.relationships.add_relationship(self.createRelation(
                                                                    action = 'contactedBy',
                                                                    src = "file[@id='%s']" % self.results['file']['md5'],
                                                                    dst = "uri[@id='%s']" % req['uri']
                                                                    )
                                                )
            
    def createRelation(self, action, src, dst):
        """
        Creates a relation between objects.
        @param action: relation type
        @param src: relation source
        @param dst: relation target
        @return: relation object
        """   
        return maec.relationship(
                                id = self.getRelId(),
                                type_ = action,
                                source = maec.reference(
                                                        valueOf_ = src
                                                        ),
                                target = maec.reference(
                                                        valueOf_ = dst
                                                        )
                                )            
        
    def createIpObject(self, ip):
        """
        Creates an single IP object, not an IP range object.
        @param ip: IP address
        @return: IP object
        """
        return maec.IPObject(
                             id = "%s-%s" % (ip, ip),
                             startAddress = maec.IPAddress(
                                                           type_ = 'ipv4',
                                                           valueOf_ = ip
                                                           ),
                             endAddress = maec.IPAddress(
                                                           type_ = 'ipv4',
                                                           valueOf_ = ip
                                                           )
                             )
        
    def createUriObject(self, req):
        """
        Creates URI object
        @param req: HTTP request as described in cuckoo dict
        @return: created URI object
        """
        uri = maec.uriObject(
                             id = req['uri'],
                             uriString = req['uri'],
                             protocol = 'http',
                             hostname = req['host'],
                             port = req['port'],
                             path = req['path'],
                             ipProtocol = 'tcp'
                             )
        # Add details
        prop = maec.objectProperty()
        prop.add_property(maec.property(
                                        type_= 'httpMethod',
                                        valueOf_ = req['method']
                                        )
                          )
        if req['method'] == 'POST':
            prop.add_property(maec.property(
                                        type_= 'postData',
                                        valueOf_ = "<![CDATA[%s]]>" % req['body']
                                        )
                          )
        if req.has_key('user-agent'):
            prop.add_property(maec.property(
                                        type_= 'userAgent',
                                        valueOf_ = req['user-agent']
                                        )
                          )    
        prop.set_references(
                            maec.reference(
                                           valueOf_ = "uri[@id='%s']" % req['uri']
                                           )
                            ) 
        self.properties.add_objectProperty(prop)
        return uri
        
    def output(self):
        """
        Writes report to disk.
        """
        try:
            report = open(os.path.join(self.report_path, "report.metadata.xml"), "w")
            report.write('<?xml version="1.0" ?>\n')
            report.write('<!--\n')
            report.write('Cuckoo Sandbox malware analysis report\n')
            report.write('http://www.cuckoobox.org\n')
            report.write('-->\n')
            self.m.export(report, 0, namespace_ = '', namespacedef_ = 'xmlns="http://xml/metadataSharing.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xml/metadataSharing.xsd"')
            report.close()
        except Exception, e:
            print "Failed writing MAEC metadata report: %s" % e


