# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gridfs
import pymongo
import re

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
        return self.db.analysis.find({"target.file.name": {"$regex": value, "$options": "-i"}})

    def search_filetype(self, value):
        return self.db.analysis.find({"target.file.type": {"$regex": value, "$options": "-i"}})

    def search_string(self, value):
        return self.db.analysis.find({"strings": {"$regex": value, "$options": "-i"}})

    def search_ssdeep(self, value):
        return self.db.analysis.find({"target.file.ssdeep": {"$regex": value, "$options": "-i"}})

    def search_crc32(self, value):
        return self.db.analysis.find({"target.file.crc32": {"$regex": value, "$options": "-i"}})

    def search_file(self, value):
        return self.db.analysis.find({"behavior.summary.files": {"$regex": value, "$options": "-i"}})

    def search_key(self, value):
        return self.db.analysis.find({"behavior.summary.keys": {"$regex": value, "$options": "-i"}})

    def search_mutex(self, value):
        return self.db.analysis.find({"behavior.summary.mutex": {"$regex": value, "$options": "-i"}})

    def search_domain(self, value):
        return self.db.analysis.find({"network.domains.domain": {"$regex": value, "$options": "-i"}})

    def search_ip(self, value):
        return self.db.analysis.find({"network.hosts": {"$regex": value, "$options": "-i"}})

    def search_signature(self, value):
        return self.db.analysis.find({ "$or": [{"signatures.families": {"$regex": value, "$options": "-i"}},
                                               {"signatures.name": {"$regex": value, "$options": "-i"}},
                                               {"signatures.marks.call.api": {"$regex": value, "$options": "-i"}},
                                               {"signatures.description": {"$regex": value, "$options": "-i"}}]})

    def search_url(self, value):
        return self.db.analysis.find({ "$or": [{"target.url": {"$regex": value, "$options": "-i"}},
                                               {"target.file.urls": {"$regex": value, "$options": "-i"}}]})

    def search_imphash(self, value):
        return self.db.analysis.find({"static.pe_imphash": {"$regex": value, "$options": "-i"}})

    def search_md5(self, value):
        return self.db.analysis.find({"target.file.md5": {"$regex": value, "$options": "-i"}})

    def search_sha1(self, value):
        return self.db.analysis.find({"target.file.sha1": {"$regex": value, "$options": "-i"}})

    def search_sha256(self, value):
        return self.db.analysis.find({"target.file.sha256": {"$regex": value, "$options": "-i"}})

    def search_sha512(self, value):
        return self.db.analysis.find({"target.file.sha512": {"$regex": value, "$options": "-i"}})

    def search_process_args(self, value):
        return self.db.analysis.find({"behavior.processes.command_line": {"$regex": value, "$options": "-i"}})

    def search_regkey_read(self, value):
        return self.db.analysis.find({"behavior.summary.regkey_read": {"$elemMatch": {"$regex": value, "$options": "-i"}}})

    def search_regkey_opened(self, value):
        return self.db.analysis.find({"behavior.summary.regkey_opened": {"$elemMatch": {"$regex": value, "$options": "-i"}}})

    def search_regkey_written(self, value):
        return self.db.analysis.find({"behavior.summary.regkey_written": {"$elemMatch": {"$regex": value, "$options": "-i"}}})

    def search(self, term, value):
        if not self.enabled:
            return

        results = []
        search_utils = {
            "name": [self.search_filename],
            "type": [self.search_filetype],
            "string": [self.search_string],
            "ssdeep": [self.search_ssdeep],
            "crc32": [self.search_crc32],
            "file": [self.search_file],
            "key": [self.search_key],
            "mutex": [self.search_mutex],
            "domain": [self.search_domain],
            "ip": [self.search_ip],
            "signature": [self.search_signature],
            "url": [self.search_url],
            "imphash": [self.search_imphash],
            "args": [self.search_process_args],
            "regkey_read": [self.search_regkey_read],
            "regkey_opened": [self.search_regkey_opened],
            "regkey_written": [self.search_regkey_written],
            "registry" : [self.search_regkey_read, self.search_regkey_opened, self.search_regkey_written],
            "hash": [self.search_md5, self.search_sha1, self.search_sha256, self.search_sha512],
            "md5": [self.search_md5],
            "sha1": [self.search_sha1],
            "sha256": [self.search_sha256],
            "sha512": [self.search_sha512],
        }

        if term in search_utils.keys():
            for handler in search_utils[term]:
                result = handler(value)
                if result:
                    results.append(result.sort([["_id", -1]]))

        return results

mongo = Mongo()
