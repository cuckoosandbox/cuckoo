# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooOperationalError


class Elastic(object):
    def __init__(self):
        self.client = None

        self.enabled = None
        self.hosts = None
        self.calls_index = None
        self.report_index = None
        self.irma_index = None
        self.index_time_pattern = None
        self.cuckoo_node = None
        self.timeout = None

    def init(self):
        self.enabled = config("reporting:elasticsearch:enabled")
        self.hosts = config("reporting:elasticsearch:hosts")
        self.timeout = config("reporting:elasticsearch:timeout")
        self.calls_index = config("reporting:elasticsearch:calls_index")
        self.report_index = config("reporting:elasticsearch:reports_index")
        self.irma_index = config("reporting:elasticsearch:irma_index")
        self.index_time_pattern = config(
            "reporting:elasticsearch:index_time_pattern"
        )
        self.cuckoo_node = config("reporting:elasticsearch:cuckoo_node")
        return self.enabled

    def connect(self):
        # TODO Option to throw an exception?
        if not self.enabled:
            return

        import elasticsearch

        try:
            self.client = elasticsearch.Elasticsearch(
                self.hosts, timeout=self.timeout
            )
        except TypeError as e:
            raise CuckooOperationalError(
                "Unable to connect to ElasticSearch due to an invalid ip:port "
                "pair: %s" % e
            )
        except elasticsearch.ConnectionError as e:
            raise CuckooOperationalError(
                "Unable to connect to ElasticSearch: %s" % e
            )

elastic = Elastic()
