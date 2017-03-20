# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gridfs
import pymongo
import re

from cuckoo.core.database import Database
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooOperationalError

class Mongo(object):
    def __init__(self):
        self.client = None
        self.db = None

        self.enabled = None
        self.hostname = None
        self.port = None
        self.database = None
        self.username = None
        self.password = None
        self.grid = None

    def init(self):
        self.enabled = config("reporting:mongodb:enabled")
        self.hostname = config("reporting:mongodb:host")
        self.port = config("reporting:mongodb:port")
        self.database = config("reporting:mongodb:db")
        self.username = config("reporting:mongodb:username")
        self.password = config("reporting:mongodb:password")
        return self.enabled

    def connect(self):
        if not self.enabled:
            return

        try:
            self.client = pymongo.MongoClient(self.hostname, self.port)
            self.db = self.client[self.database]
            if self.username and self.password:
                self.db.authenticate(self.username, self.password)
            self.grid = gridfs.GridFS(self.db)
        except pymongo.errors.PyMongoError as e:
            raise CuckooOperationalError(
                "Unable to connect to MongoDB: %s" % e
            )

    def drop(self):
        if not self.enabled:
            return

        try:
            if self.client and self.database in self.client.database_names():
                self.client.drop_database(self.database)
        except TypeError as e:
            raise CuckooOperationalError(
                "Unable to find Database %s in MongoDB: %s" %(self.database,e)
            )
        except pymongo.errors.PyMongoError as e:
            raise CuckooOperationalError(
                "Unable to connect to MongoDB: %s" % e
            )

    def search_filename(self, value):
        return self.db.analysis.find({"target.file.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_filetype(self, value):
        return self.db.analysis.find({"target.file.type": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_string(self, value):
        return self.db.analysis.find({"strings": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_ssdeep(self, value):
        return self.db.analysis.find({"target.file.ssdeep": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_crc32(self, value):
        return self.db.analysis.find({"target.file.crc32": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_file(self, value):
        return self.db.analysis.find({"behavior.summary.files": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_key(self, value):
        return self.db.analysis.find({"behavior.summary.keys": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_mutex(self, value):
        return self.db.analysis.find({"behavior.summary.mutex": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_domain(self, value):
        return self.db.analysis.find({"network.domains.domain": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_ip(self, value):
        return self.db.analysis.find({"network.hosts": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_signature(self, value):
        return self.db.analysis.find({ "$or": [{"signatures.families": {"$regex": value, "$options": "-i"}},
                                               {"signatures.name": {"$regex": value, "$options": "-i"}},
                                               {"signatures.marks.call.api": {"$regex": value, "$options": "-i"}},
                                               {"signatures.description": {"$regex": value, "$options": "-i"}}]}).sort([["_id", -1]])

    def search_url(self, value):
        return self.db.analysis.find({ "$or": [{"target.url": {"$regex": value, "$options": "-i"}},
                                               {"target.file.urls": {"$regex": value, "$options": "-i"}}]}).sort([["_id", -1]])

    def search_imphash(self, value):
        return self.db.analysis.find({"static.pe_imphash": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_md5(self, value):
        return self.db.analysis.find({"target.file.md5": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_sha1(self, value):
        return self.db.analysis.find({"target.file.sha1": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_sha256(self, value):
        return self.db.analysis.find({"target.file.sha256": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_sha512(self, value):
        return self.db.analysis.find({"target.file.sha512": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_process_args(self, value):
        return self.db.analysis.find({"behavior.processes.command_line": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])

    def search_regkey_read(self, value):
        return self.db.analysis.find({"behavior.summary.regkey_read": {"$elemMatch": {"$regex": value, "$options": "-i"}}}).sort([["_id", -1]])

    def search_regkey_opened(self, value):
        return self.db.analysis.find({"behavior.summary.regkey_opened": {"$elemMatch": {"$regex": value, "$options": "-i"}}}).sort([["_id", -1]])

    def search_regkey_written(self, value):
        return self.db.analysis.find({"behavior.summary.regkey_written": {"$elemMatch": {"$regex": value, "$options": "-i"}}}).sort([["_id", -1]])

    def extract_database(self, results):
        # Get data from cuckoo db
        db = Database()
        analyses = []

        for result in results:
            new = db.view_task(result["info"]["id"])

            if not new:
                continue

            new = new.to_dict()

            if result["info"]["category"] == "file":
                if new["sample_id"]:
                    sample = db.view_sample(new["sample_id"])
                    if sample:
                        new["sample"] = sample.to_dict()

            analyses.append(new)
        return analyses

    def search(self, term, value):
        if not self.enabled:
            return

        results = []
        if term == "name":
            results = self.search_filename(value)
        elif term == "type":
            results = self.search_filetype(value)
        elif term == "string":
            results = self.search_string(value)
        elif term == "ssdeep":
            results = self.search_ssdeep(value)
        elif term == "crc32":
            results = self.search_crc32(value)
        elif term == "file":
            results = self.search_file(value)
        elif term == "key":
            results = self.search_key(value)
        elif term == "mutex":
            results = self.search_mutex(value)
        elif term == "domain":
            results = self.search_domain(value)
        elif term == "ip":
            results = self.search_ip(value)
        elif term == "signature":
            results = self.search_signature(value)
        elif term == "url":
            results = self.search_url(value)
        elif term == "imphash":
            results = self.search_imphash(value)
        elif term == "args":
            results = self.search_process_args(value)
        elif term == "regkey_read":
            results = self.search_regkey_read(value)
        elif term == "regkey_opened":
            results = self.search_regkey_opened(value)
        elif term == "regkey_written":
            results = self.search_regkey_written(value)
        elif term == None:
            if re.match(r"^([a-fA-F\d]{32})$", value):
                results = self.search_md5(value)
            elif re.match(r"^([a-fA-F\d]{40})$", value):
                results = self.search_sha1(value)
            elif re.match(r"^([a-fA-F\d]{64})$", value):
                results = self.search_sha256(value)
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                results = self.search_sha512(value)

        results = self.extract_database(results)[:16]
        return results

mongo = Mongo()
