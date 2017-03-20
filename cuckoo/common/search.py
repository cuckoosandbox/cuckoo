# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
from cuckoo.common.elastic import elastic
from cuckoo.common.mongo import mongo


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

    def find(self, term, value):
        """Combines ElasticSearch and MongoDB for search"""
        value = re.escape(value.lstrip().lower())
        term = term.rstrip() if term else term

        assert self.mongo.enabled == True

        # Search for hashes like md5 or sha1 or sha256 or sha512
        if not term or term == "regkey_read" or term=="regkey_opened" or term=="regkey_written" or term == "file_written"\
                or term == "file_deleted" or term == "file_created" or term == "file_moved" or term == "file_opened"\
                or term == "file_recreated":
            return self.mongo.search(term, value) + self.elastic.search(term, value)
        # Search for whatever we can extract from ES
        elif term == "buffer" or term == "dropped":
            return self.elastic.search(term, value)
        # Extract remaining from MongoDB
        else:
            return self.mongo.search(term, value)


searcher = Search()
