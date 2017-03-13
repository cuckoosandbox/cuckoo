# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

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
        print term, value
        value = value.lstrip().lower()
        term = term.rstrip() if term else term
        if self.mongo.enabled:
            return self.mongo.search(term, value)
        else:
            return self.elastic.search(term, value)


searcher = Search()
