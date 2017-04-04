# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import datetime
import elasticsearch.helpers
import json
import logging
import time
import os

from cuckoo.common.abstracts import Report
from cuckoo.common.elastic import elastic
from cuckoo.common.exceptions import CuckooReportError, CuckooOperationalError
from cuckoo.misc import cwd

logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elasticsearch.trace").setLevel(logging.WARNING)

log = logging.getLogger(__name__)

class ElasticSearch(Report):
    """Stores report in Elasticsearch."""

    @classmethod
    def init_once(cls):
        """Connect to Elasticsearch.
        @raise CuckooReportError: if unable to connect.
        """
        # Do not change these types without changing the elasticsearch
        # template as well.
        cls.report_type = "cuckoo"
        cls.call_type = "call"

        if not elastic.init():
            return

        cls.template_name = "%s_template" % elastic.index

        try:
            elastic.connect()
        except CuckooOperationalError as e:
            raise CuckooReportError(
                "Error running ElasticSearch reporting module: %s" % e
            )

        # check to see if the template exists apply it if it does not
        if not elastic.client.indices.exists_template(cls.template_name):
            if not cls.apply_template():
                raise CuckooReportError("Cannot apply Elasticsearch template")

    @classmethod
    def apply_template(cls):
        template_path = cwd("elasticsearch", "template.json")
        if not os.path.exists(template_path):
            return False

        try:
            template = json.loads(open(template_path, "rb").read())
        except ValueError:
            raise CuckooReportError(
                "Unable to read valid JSON from the ElasticSearch "
                "template JSON file located at: %s" % template_path
            )

        # Create an index wildcard based off of the index name specified
        # in the config file, this overwrites the settings in
        # template.json.
        template["template"] = elastic.index + "-*"

        # if the template does not already exist then create it
        if not elastic.client.indices.exists_template(cls.template_name):
            elastic.client.indices.put_template(
                name=cls.template_name, body=json.dumps(template)
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
        base_document = self.get_base_document()

        # Append the base document to the object to index.
        base_document.update(obj)

        try:
            elastic.client.index(
                index=self.dated_index,
                doc_type=self.report_type,
                body=base_document
            )
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def do_bulk_index(self, bulk_reqs):
        try:
            elasticsearch.helpers.bulk(elastic.client, bulk_reqs)
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
                            new_mark["%s_dict" % k] = v
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
        # Gets the time which will be used for indexing the document into ES
        # ES needs epoch time in seconds per the mapping
        self.report_time = int(time.time())

        # Get the index time option and set the dated index accordingly
        date_index = datetime.datetime.utcnow().strftime({
            "yearly": "%Y",
            "monthly": "%Y-%m",
            "daily": "%Y-%m-%d",
        }[elastic.index_time_pattern])
        self.dated_index = "%s-%s" % (elastic.index, date_index)

        # Index target information, the behavioral summary, and
        # VirusTotal results.
        doc = {
            "cuckoo_node": elastic.cuckoo_node,
            "target": results.get("target"),
            "summary": results.get("behavior", {}).get("summary"),
            "info": results.get("info"),
        }

        # index elements that are not empty ES should not index blank fields
        virustotal = results.get("virustotal")
        if virustotal:
            doc["virustotal"] = virustotal

        irma = results.get("irma")
        if irma:
            doc["irma"] = irma

        signatures = results.get("signatures")
        if signatures:
            doc["signatures"] = self.process_signatures(signatures)

        dropped = results.get("dropped")
        if dropped:
            doc["dropped"] = dropped

        procmemory = results.get("procmemory")
        if procmemory:
            doc["procmemory"] = procmemory

        self.do_index(doc)

        # Index the API calls.
        if elastic.calls:
            self.process_behavior(results)
