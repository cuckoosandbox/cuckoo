# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import json
import sys

class Cuckooml(object):
    """Machine Learning for Cuckoo."""
    LABEL_SIGNIFICANCE_COUNT = 5
    POSITIVE_RATE = 2 * LABEL_SIGNIFICANCE_COUNT

    def __init__(self):
        self.report = None
        self.total = None
        self.positives = None
        self.scans = None
        self.label = None


    def load_json(self, json_path):
        """Load JSON formatted malware report."""
        with open(json_path, "r") as malware_report:
            try:
                self.report = json.load(malware_report)
            except ValueError, error:
                print >> sys.stderr, "Could not load file;", \
                    malware_report, "is not a valid JSON file."
                print >> sys.stderr, "Exception: %s" % str(error)
                sys.exit(1)

        # Get total and positives
        self.total = self.report.get("virustotal").get("total")
        self.positives = self.report.get("virustotal").get("positives")
        # Pull all VT normalised results
        self.scans = self.report.get("virustotal").get("scans")


    def label_sample(self, external_labels=None, label_type="family"):
        """Generate label for the loaded sample.
        You can use platform, cve, metatype, type, and family (default)."""
        merged_labels = []

        if external_labels is None and self.scans is not None:
            for vendor in self.scans:
                merged_labels += self.scans[vendor]["normalized"][label_type]
        elif external_labels is not None and self.scans is None:
            merged_labels = external_labels

        if not merged_labels:
            self.label = "none"
            return

        # Get most common label if it has more hits than set threshold
        labels_frequency = collections.Counter(merged_labels)
        top_label, top_label_count = labels_frequency.most_common(1)[0]
        if top_label_count >= self.LABEL_SIGNIFICANCE_COUNT:
                # self.positives >= self.POSITIVE_RATE:
            self.label = top_label.encode("ascii", "ignore")
        else:
            self.label = "none"
