# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import json
import sys

class ML(object):
    """Feature formatting and machine learning for Cuckoo analysed binaries."""
    def __init__(self):
        pass


class Instance(object):
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


    def extract_features(self):
        """Extract features of the loaded sample."""
        self.extract_features_static()
        self.extract_features_dynamic()


    def extract_features_static(self):
        """Extract static features of the loaded sample."""
        self.feature_static_metadata()
        self.feature_static_signature()
        self.feature_static_heuristic()
        self.feature_static_packer()
        self.feature_static_pef()
        self.feature_static_imports()


    def extract_features_dynamic(self):
        """Extract dynamic features of the loaded sample."""
        self.feature_dynamic_imports()
        self.feature_dynamic_filesystem()
        self.feature_dynamic_network()
        self.feature_dynamic_registry()
        self.feature_dynamic_windowsapi()


    def feature_static_metadata(self):
        """Create features form extracted binary metadata."""
        print self.report.get("target").get("file").get("size")
        print self.report.get("target", {}).get("file", {}).get("type")
        print self.report.get("static", {}).get("pe_timestamp")
        print self.report.get("static", {}).get("pe_versioninfo")


    def feature_static_signature(self):
        """Create features form binary signature check."""
        print self.report.get("static", {}).get("signature")
        print self.report.get("static", {}).get("pe_versioninfo")


    def feature_static_heuristic(self):
        """Create features form results return by heuristic tools.
        **Not available for current JSON content.**"""
        pass


    def feature_static_packer(self):
        """Create feature from information returned by packer/cryptor
        detectors."""
        print self.report.get("static", {}).get("peid_signatures")


    def feature_static_pef(self):
        """Create features from information derived form portable executable
        format."""
        print self.report.get("static", {}).get("pe_sections")
        print self.report.get("static", {}).get("pe_resources")


    def feature_static_imports(self):
        """Extract features from static imports like referenced library
        functions."""
        print self.report.get("static", {}).get("imported_dll_count")
        print self.report.get("static", {}).get("pe_imports")
        print self.report.get("static", {}).get("pe_exports")


    def feature_dynamic_imports(self):
        """Extract features from dynamic imports, mutexes, and processes."""
        pass


    def feature_dynamic_filesystem(self):
        """Extract features from filesystem operations."""
        pass


    def feature_dynamic_network(self):
        """Extract features from network operations."""
        pass


    def feature_dynamic_registry(self):
        """Extract features from registry operations."""
        pass


    def feature_dynamic_windowsapi(self):
        """Extract features from Windows API calls sequence."""
        pass
