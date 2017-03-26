# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import datetime
import json
import logging
import time
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError

logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elasticsearch.trace").setLevel(logging.WARNING)

try:
    from elasticsearch import (
        Elasticsearch, ConnectionError, ConnectionTimeout, helpers
    )

    HAVE_ELASTIC = True
except ImportError:
    HAVE_ELASTIC = False

log = logging.getLogger(__name__)


class ElasticSearch(Report):
    """Stores report in Elasticsearch."""

    def connect(self):
        """Connect to Elasticsearch.
        @raise CuckooReportError: if unable to connect.
        """
        hosts = []
        for host in self.options.get("hosts", "127.0.0.1:9200").split(","):
            if host.strip():
                hosts.append(host.strip())

        self.index = self.options.get("index", "cuckoo")

        # Do not change these types without changing the elasticsearch
        # template as well.
        self.report_type = "cuckoo"
        self.call_type = "call"

        # Get the index time option and set the dated index accordingly
        index_type = self.options.get("index_time_pattern", "yearly")
        if index_type.lower() == "yearly":
            strf_time = "%Y"
        elif index_type.lower() == "monthly":
            strf_time = "%Y-%m"
        elif index_type.lower() == "daily":
            strf_time = "%Y-%m-%d"

        date_index = datetime.datetime.utcnow().strftime(strf_time)
        self.dated_index = "%s-%s" % (self.index, date_index)

        # Gets the time which will be used for indexing the document into ES
        # ES needs epoch time in seconds per the mapping
        self.report_time = int(time.time())

        self.template_name = self.index + "_template"

        try:
            # increase the default timeout from 10 seconds to 5 minutes
            # this will help with indexing huge reports on slower non clustered
            # elasticsearch instances
            elasticsearch_timeout = self.options.get("timeout", 60*5)
            self.es = Elasticsearch(hosts, timeout=elasticsearch_timeout)
        except TypeError:
            raise CuckooReportError(
                "Elasticsearch connection hosts must be host:port or host"
            )
        except (ConnectionError, ConnectionTimeout) as e:
            raise CuckooReportError("Cannot connect to Elasticsearch: %s" % e)

        # check to see if the template exists apply it if it does not
        if not self.es.indices.exists_template(self.template_name):
            if not self.apply_template():
                raise CuckooReportError("Cannot apply Elasticsearch template")

    def apply_template(self):
        template_path = os.path.join(
            CUCKOO_ROOT, "data", "elasticsearch", "template.json"
        )
        if not os.path.exists(template_path):
            return False

        with open(template_path, "r") as f:
            try:
                cuckoo_template = json.loads(f.read())
            except ValueError:
                raise CuckooReportError(
                    "Unable to read valid JSON from the ElasticSearch "
                    "template JSON file located at: %s" % template_path
                )

            # Create an index wildcard based off of the index name specified
            # in the config file, this overwrites the settings in
            # template.json.
            cuckoo_template["template"] = self.index + "-*"

        # if the template does not already exist then create it
        if self.es.indices.exists_template(self.template_name):
            self.es.indices.put_template(
                name=self.template_name, body=json.dumps(cuckoo_template)
            )
        return True

    def get_base_document(self):
        # Gets precached report time and the task_id.
        header = {
            "task_id": self.task["id"],
            "report_time": self.report_time,
            "report_id": self.task["id"]
        }
        return header

    def do_index(self, obj):
        index = self.dated_index

        base_document = self.get_base_document()

        # Append the base document to the object to index.
        base_document.update(obj)

        try:
            self.es.index(
                index=index, doc_type=self.report_type, body=base_document
            )
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def do_bulk_index(self, bulk_reqs):
        try:
            helpers.bulk(self.es, bulk_reqs)
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def process_signatures(self, signatures):
        new_signatures = []

        for signature in signatures:
            new_signature = signature.copy()

            if "marks" in signature:
                new_signature["marks"] = []
                for mark in signature["marks"]:
                    new_mark = {}
                    for k, v in mark.iteritems():
                        if k != "call" and type(v) == dict:
                            # If marks is a dictionary we need to explicitly define it for the ES mapping
                            # this is in the case that a key in marks is sometimes a string and sometimes a dictionary
                            # if the first document indexed into ES is a string it will not accept a signature
                            # and through a ES mapping exception.  To counter this dicts will be explicitly stated
                            # in the key except for calls which are always dictionaries.
                            # This presented itself in testing with signatures.marks.section which would sometimes be a
                            # PE section string such as "UPX"  and other times full details about the section as a
                            # dictionary in the case of packer_upx and packer_entropy signatures
                            new_mark[k+"_dict"] = v
                        else:
                            # If it is not a mark it is fine to leave key as is
                            new_mark[k] = v

                    new_signature["marks"].append(new_mark)

            new_signatures.append(new_signature)

        return new_signatures

    def process_behavior(self, results, bulk_submit_size=1000):
        """Index the behavioral data."""
        for process in results.get("behavior", {}).get("processes", []):
            bulk_index = []

            for call in process["calls"]:
                base_document = self.get_base_document()
                call_document = {
                    "pid": process["pid"],
                }
                call_document.update(call)
                call_document.update(base_document)
                bulk_index.append({
                    "_index": self.dated_index,
                    "_type": self.call_type,
                    "_source": call_document
                })
                if len(bulk_index) == bulk_submit_size:
                    self.do_bulk_index(bulk_index)
                    bulk_index = []

            if len(bulk_index) > 0:
                self.do_bulk_index(bulk_index)

    def run(self, results):
        """Index the Cuckoo report into ElasticSearch.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if the connection or reporting failed.
        """
        if not HAVE_ELASTIC:
            raise CuckooDependencyError(
                "Unable to import elasticsearch (install with "
                "`pip install elasticsearch`)"
            )

        self.connect()

        # Index target information, the behavioral summary, and
        # VirusTotal results.
        doc = dict()

        # index elements that will never be empty
        doc["cuckoo_node"] = self.options.get("cuckoo_node")
        doc["target"] = results.get("target")
        doc["summary"] = results.get("behavior", {}).get("summary")
        doc["info"] = results.get("info")

        # index elements that are not empty ES should not index blank fields
        virustotal = results.get("virustotal")
        if virustotal:
            doc["virustotal"] = virustotal

        irma = results.get("irma")
        if irma:
            doc["irma"] = irma

        signatures = results.get("signatures")
        if signatures:
            signatures = self.process_signatures(signatures)
            doc["signatures"] = signatures

        dropped = results.get("dropped")
        if dropped:
            doc["dropped"] = dropped

        procmemory = results.get("procmemory")
        if procmemory:
            doc["procmemory"] = procmemory

        self.do_index(doc)

        # Index the API calls.
        if self.options.get("calls"):
            self.process_behavior(results)
