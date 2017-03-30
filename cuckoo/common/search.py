# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
from cuckoo.common.elastic import elastic
from cuckoo.common.mongo import mongo
from cuckoo.core.database import Database

from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class Search(object):
    """
    Search class. Decides which DB abstract layer to use,
    ElasticSearch or MongoDB.
    """

    def __init__(self):
        self.enabled = (elastic.enabled or mongo.enabled)

        self.mongo = mongo
        self.elastic = elastic
        return

    def mongo_extract_database(self, allresults):
        # Get data from cuckoo db
        db = Database()
        analyses = []

        for results in allresults:
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

    def is_md5(self, text):
        if re.match(r"^([a-fA-F\d]{32})$", text):
            return True
        return False

    def is_sha1(self, text):
        if re.match(r"^([a-fA-F\d]{40})$", text):
            return True
        return False

    def is_sha256(self, text):
        if re.match(r"^([a-fA-F\d]{64})$", text):
            return True
        return False

    def is_sha512(self, text):
        if re.match(r"^([a-fA-F\d]{128})$", text):
            return True
        return False

    def is_crc32(self, text):
        if re.match(r"^([A-Fa-f0-9]{8})$", text):
            return True
        return False

    def is_ip(self, text):
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", text):
            return True
        return False

    def is_url(self, text):
        val = URLValidator()
        try:
            val(text)
            return True
        except ValidationError as e:
            return False

    def find(self, term, value):
        """Combines ElasticSearch and MongoDB for search"""

        value = value.lstrip().lower()
        term = term.rstrip() if term else term

        assert self.mongo.enabled == True

        mongo_elastic_queries = ["regkey_read", "regkey_opened", "regkey_written", "file_written", "file_deleted", "file_created", "file_moved", "file_opened", "file_recreated"]
        elastic_queries = ["buffer", "dropped"]
        type_guesser = {
            "md5": self.is_md5,
            "sha1": self.is_sha1,
            "sha256": self.is_sha256,
            "sha512": self.is_sha512,
            "crc32": self.is_crc32,
            # "": r"",    # type
            # "": r"",    # mutexes
            # "domain": self.is_domain,
            "ip": self.is_ip,
            "url": self.is_url,
            # "": r"",    # imphash
            # "": r"",    # registry
        }

        if term is None:
            for key in type_guesser.keys():
                if type_guesser[key](value):
                    term = key
                    break
        value = re.escape(value)

        if not term or term in mongo_elastic_queries:
            mongo_results = self.mongo.search(term, value)
            elastic_results = self.elastic.search(term, value)
            return self.mongo_extract_database(mongo_results) + elastic_results
        elif term in elastic_queries:
            return self.elastic.search(term, value)
        else:
            mongo_results = self.mongo.search(term, value)
            return self.mongo_extract_database(mongo_results)


searcher = Search()
