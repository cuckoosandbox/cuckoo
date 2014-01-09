# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import os
import hashlib

import lib.maec.maec11 as maec
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.utils import datetime_to_iso


class MMDef(Report):
    """Generates a MAEC Malware Metadata Sharing report."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        # Save results.
        self.results = results
        # Reporting steps.
        self.addMetadata()
        self.addObjects()
        self.addRelations()
        # Write report.
        self.output()

    def addMetadata(self):
        """Generates header for MAEC xml and root components."""
        if self.results["target"]["category"] == "file":
            id = "cuckoo:%s" % self.results["target"]["file"]["md5"]
        elif self.results["target"]["category"] == "url":
            id = "cuckoo:%s" % hashlib.md5(self.results["target"]["url"]).hexdigest()
        else:
            raise CuckooReportError("Unknown target type")

        self.m = maec.malwareMetaData(
            version="1.1",
            id=id,
            author="Cuckoo Sandbox %s" % self.results["info"]["version"],
            comment="Report created with Cuckoo Sandbox %s automated and open source malware sandbox: http://www.cuckoosandbox.org" % self.results["info"]["version"],
            timestamp=datetime_to_iso(self.results["info"]["started"])
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
        """Adds objects elements."""
        # File objects
        # Subject
        if self.results["target"]["category"] == "file":
            self.objects.add_file(self.createFileObject(self.results["target"]["file"]))
        elif self.results["target"]["category"] == "url":
            self.objects.add_uri(maec.uriObject(
                                                id=hashlib.md5(self.results["target"]["url"]).hexdigest(),
                                                uriString=self.results["target"]["url"])
                                 )
        else:
            raise CuckooReportError("Unknown target type")

        # Dropped files
        if "dropped" in self.results and isinstance(self.results["dropped"], list):
            for f in self.results["dropped"]:
                found = False
                for exist in self.objects.get_file():
                    if exist.get_md5() == f["md5"]:
                        found = True
                if not found:        
                    self.objects.add_file(self.createFileObject(f))
        # URI objects
        if "network" in self.results and isinstance(self.results["network"], dict):
            if "http" in self.results["network"] and isinstance(self.results["network"]["http"], list): 
                for req in self.results["network"]["http"]:
                    found = False
                    for exist in self.objects.get_uri():
                        if exist.get_id() == req["uri"]:
                            found = True
                    if not found:
                        self.objects.add_uri(self.createUriObject(req))

    def createFileObject(self, f):
        """Creates a file object.
        @param f: file hash representation from cuckoo dict results.
        @return: file object.
        """
        file = maec.fileObject(
                               id=f["md5"],
                               fileType=[f["type"]],
                               size=f["size"],
                               crc32=f["crc32"],
                               md5=f["md5"],
                               sha1=f["sha1"],
                               sha512=f["sha512"]
                               )
        file.add_extraHash(maec.extraHashType("ssdeep", f["ssdeep"]))
        # Add related filename
        prop = maec.objectProperty()
        prop.add_property(maec.property(
                                        type_="filename",
                                        valueOf_=f["name"]
                                        )
                          )
        prop.set_references(
                            maec.reference(
                                           valueOf_="file[@id='%s']" % f["md5"]
                                           )
                            ) 
        self.properties.add_objectProperty(prop)
        return file

    def getRelId(self):
        """Generates incremental relation id.
        @return: generated id
        """
        try:
            self.relId = self.relId +1
        except AttributeError:
            self.relId = 1
        return self.relId

    def addRelations(self):
        """Adds relationships."""
        if self.results["target"]["category"] == "file":
            src = "file[@id='%s']" % self.results["target"]["file"]["md5"]
        elif self.results["target"]["category"] == "url":
            src = "url[@id='%s']" % hashlib.md5(self.results["target"]["url"]).hexdigest()
        
        # Dropped files
        for file in self.results["dropped"]:
            self.relationships.add_relationship(self.createRelation(
                                                                    action="installed",
                                                                    src=src,
                                                                    dst="file[@id='%s']" % file["md5"]
                                                                    )
                                                )
        # Network
        if "network" in self.results and isinstance(self.results["network"], dict):
            # DNS requests
            for req in self.objects.get_uri():
                # Get IP
                if "domains" in self.results["network"] and isinstance(self.results["network"]["domains"], list):
                    for res in self.results["network"]["domains"]: 
                        if res["domain"] == req.get_hostname():
                            ip = res["ip"]
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
                                                                                    action="isServerOfService",
                                                                                    src="ip[@id='%s']" % found.id,
                                                                                    dst="uri[@id='%s']" % req.id
                                                                                    )
                                                                )
            # HTTP requests
            if "http" in self.results["network"] and isinstance(self.results["network"]["http"], list):
                for req in self.results["network"]["http"]:
                    self.relationships.add_relationship(self.createRelation(
                                                                            action="contactedBy",
                                                                            src=src,
                                                                            dst="uri[@id='%s']" % req["uri"]
                                                                            )
                                                        )

    def createRelation(self, action, src, dst):
        """Creates a relation between objects.
        @param action: relation type
        @param src: relation source
        @param dst: relation target
        @return: relation object
        """
        return maec.relationship(
                                id=self.getRelId(),
                                type_=action,
                                source=maec.reference(
                                                        valueOf_=src
                                                        ),
                                target=maec.reference(
                                                        valueOf_=dst
                                                        )
                                )

    def createIpObject(self, ip):
        """Creates an single IP object, not an IP range object.
        @param ip: IP address
        @return: IP object
        """
        return maec.IPObject(
                             id="%s-%s" % (ip, ip),
                             startAddress=maec.IPAddress(
                                                           type_="ipv4",
                                                           valueOf_=ip
                                                           ),
                             endAddress=maec.IPAddress(
                                                           type_="ipv4",
                                                           valueOf_=ip
                                                           )
                             )

    def createUriObject(self, req):
        """Creates URI object
        @param req: HTTP request as described in cuckoo dict
        @return: created URI object
        """
        uri = maec.uriObject(
                             id=req["uri"],
                             uriString=req["uri"],
                             protocol="http",
                             hostname=req["host"],
                             port=req["port"],
                             path=req["path"],
                             ipProtocol="tcp"
                             )
        # Add details
        prop = maec.objectProperty()
        prop.add_property(maec.property(
                                        type_="httpMethod",
                                        valueOf_=req["method"]
                                        )
                          )
        if req["method"] == "POST":
            prop.add_property(maec.property(
                                        type_="postData",
                                        valueOf_="<![CDATA[%s]]>" % req["body"]
                                        )
                          )
        if "user-agent" in req:
            prop.add_property(maec.property(
                                        type_="userAgent",
                                        valueOf_=req["user-agent"]
                                        )
                          )
        prop.set_references(
                            maec.reference(
                                           valueOf_="uri[@id='%s']" % req["uri"]
                                           )
                            )
        self.properties.add_objectProperty(prop)
        return uri

    def output(self):
        """Writes report to disk."""
        try:
            report = open(os.path.join(self.reports_path, "report.metadata.xml"), "w")
            report.write("<?xml version='1.0' ?>\n")
            report.write("<!--\n")
            report.write("Cuckoo Sandbox malware analysis report\n")
            report.write("http://www.cuckoosandbox.org\n")
            report.write("-->\n")
            self.m.export(report, 0, namespace_="", namespacedef_="xmlns='http://xml/metadataSharing.xsd' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:schemaLocation='http://xml/metadataSharing.xsd'")
            report.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate MAEC Metadata report: %s" % e)

