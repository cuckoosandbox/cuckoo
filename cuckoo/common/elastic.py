# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import elasticsearch

from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooOperationalError

class Elastic(object):
    def __init__(self):
        self.client = None

        self.enabled = None
        self.hosts = None
        self.calls = None
        self.index = None
        self.index_time_pattern = None
        self.cuckoo_node = None

    def init(self):
        self.enabled = config("reporting:elasticsearch:enabled")
        self.hosts = config("reporting:elasticsearch:hosts")
        self.calls = config("reporting:elasticsearch:calls")
        self.index = config("reporting:elasticsearch:index")
        self.index_time_pattern = config(
            "reporting:elasticsearch:index_time_pattern"
        )
        self.cuckoo_node = config("reporting:elasticsearch:cuckoo_node")
        return self.enabled

    def connect(self):
        # TODO Option to throw an exception?
        if not self.enabled:
            return

        try:
            self.client = elasticsearch.Elasticsearch(self.hosts)
        except TypeError as e:
            raise CuckooOperationalError(
                "Unable to connect to ElasticSearch due to an invalid ip:port "
                "pair: %s" % e
            )
        except elasticsearch.ConnectionError as e:
            raise CuckooOperationalError(
                "Unable to connect to ElasticSearch: %s" % e
            )

    def search_helper(self, obj, keys, term, value):
        """ Search for appropriate key/value pair """
        r = []

        if isinstance(obj, dict):
            for k, v in obj.items():
                r += self.search_helper(v, keys + [k], term, value)

        if isinstance(obj, (tuple, list)):
            for v in obj:
                r += self.search_helper(v, keys, term, value)

        if isinstance(obj, basestring):
            if re.search(value, obj, re.I):
                if not term or term in keys:
                    r.append((keys[-1] if len(keys) else "none", obj))

        return r

    def search(self, term, value):
        results = []

        if not self.enabled:
            return results

        match_value = ".*".join(re.split("[^a-zA-Z0-9]+", value))

        r = self.client.search(
            index=self.index + "-*",
            body={
                "query": {
                    "query_string": {
                        "query": '"%s"*' % value,
                    },
                },
            }
        )
        for hit in r["hits"]["hits"]:
            # Find the actual matches in this hit and limit to 16 matches.
            matches = self.search_helper(hit, [], term, match_value)
            if not matches:
                continue

            results.append({
                "task_id": hit["_source"]["report_id"],
                "matches": matches[:16],
                "total": max(len(matches) - 16, 0),
            })
        return results

elastic = Elastic()
