# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import datetime
import json
import os
import sys
import time
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.manifold import TSNE

class ML(object):
    """Feature formatting and machine learning for Cuckoo analysed binaries."""
    SIMPLE_CATEGORIES = {
        "properties":[
            "has_authenticode",
            "has_pdb",
            "pe_features",
            "packer_upx",
            "has_wmi"
        ],
        "behaviour":[
            "dumped_buffer2",
            "suspicious_process",
            "persistence_autorun",
            "raises_exception",
            "sniffer_winpcap",
            "injection_runpe",
            "dumped_buffer",
            "exec_crash",
            "creates_service",
            "allocates_rwx"
        ],
        "exploration":[
            "recon_fingerprint",
            "antidbg_windows",
            "locates_sniffer"
        ],
        "mutex":[
            "ardamax_mutexes",
            "rat_xtreme_mutexes",
            "bladabindi_mutexes"
        ],
        "networking":[
            "network_bind",
            "networkdyndns_checkip",
            "network_http",
            "network_icmp",
            "recon_checkip",
            "dns_freehosting_domain",
            "dns_tld_pw",
            "dns_tld_ru"
        ],
        "filesystem":[
            "modifies_files",
            "packer_polymorphic",
            "creates_exe",
            "creates_doc"
        ],
        "security":[
            "rat_xtreme",
            "disables_security",
            "trojan_redosru",
            "worm_renocide",
            "antivirus_virustotal"
        ],
        "virtualisation":[
            "antivm_vbox_files",
            "antivm_generic_bios",
            "antivm_vmware_keys",
            "antivm_generic_services",
            "antivm_vmware_files",
            "antivm_sandboxie",
            "antivm_vbox_keys",
            "antivm_generic_scsi",
            "antivm_vmware_in_instruction",
            "antivm_generic_disk",
            "antivm_virtualpc"
        ],
        "sanbox":[
            "antisandbox_unhook",
            "antisandbox_mouse_hook",
            "antisandbox_foregroundwindows",
            "antisandbox_productid",
            "antisandbox_idletime",
            "antisandbox_sleep"
        ],
        "infostealer":[
            "infostealer_browser",
            "infostealer_mail",
            "infostealer_keylogger",
            "infostealer_ftp",
        ],
        "ransomware":[
            "ransomware_files",
            "ransomware_bcdedit"
        ]
    }

    def __init__(self):
        self.labels = None
        self.simple_features = None
        self.simple_features_description = {}
        self.features = None


    def load_labels(self, labels):
        """Load labels into pandas data frame."""
        self.labels = pd.DataFrame(labels, index=["label"]).T


    def load_simple_features(self, simple_features):
        """Load simple features form an external object into pandas data
        frame."""
        self.simple_features = pd.DataFrame(simple_features).T
        self.simple_features.fillna(False, inplace=True)
        self.simple_features = self.simple_features.astype(bool)

        # Aggregate features descriptions
        self.simple_features_description = {}
        for binary in simple_features:
            for token in simple_features[binary]:
                if token not in self.simple_features_description:
                    self.simple_features_description[token] = \
                        simple_features[binary][token]


    def export_simple_dataset(self, filename="simple_dataset.csv"):
        """Export a dataset consisting of malware labels and *simple* features
        to CSV formatted file."""
        # Check if data and labels are loaded
        if self.simple_features is None:
            print "Please load simple features first."
            return

        if self.labels is None:
            print "Please load labels first."
            return

        simple_dataset = pd.concat([self.simple_features, self.labels], axis=1)
        simple_dataset.to_csv(filename)


    def simple_feature_category(self, category="properties"):
        """Get simple feature data frame containing only features form selected
        category."""
        if self.simple_features is None:
            print "Simple features are not loaded. Please load them before \
                   extracting categories."
            return None

        return self.simple_features.loc[:, self.SIMPLE_CATEGORIES[category]]


    def load_features(self, features):
        """Load features form an external object into pandas data frame."""
        pass
        # self.features = features


    def export_dataset(self, filename="dataset.csv"):
        """Export a dataset consisting of malware labels and features to CSV
        formatted file."""
        # Check if data and labels are loaded
        if self.features is None:
            print "Please load features first."
            return

        if self.labels is None:
            print "Please load labels first."
            return

        dataset = pd.concat([self.features, self.labels], axis=1)
        dataset.to_csv(filename)


    def visualise_data(self, data=None, labels=None, learning_rate=200,
                       fig_name="custom"):
        """Create t-Distributed Stochastic Neighbor Embedding for features and
        labels to help inspect the data."""
        if data is None:
            data = self.features
        if labels is None:
            labels = self.labels

        tsne = TSNE(learning_rate=learning_rate)
        tsne_fit = tsne.fit_transform(data)
        tsne_df = pd.DataFrame(tsne_fit, index=data.index, columns=['0', '1'])
        tsne_dfl = pd.concat([tsne_df, labels], axis=1)

        sns.lmplot('0', '1', data=tsne_dfl, fit_reg=False, hue='label',
                   scatter_kws={"marker":"D", "s":50}, legend_out=True)
        plt.title(fig_name + " (lr:" + str(learning_rate) + ")")
        plt.savefig(fig_name + "_" + str(learning_rate) + ".png",
                    bbox_inches='tight', pad_inches=1.)
        plt.close()


class Loader(object):
    """Loads instances for analysis and give possibility to extract properties
    of interest."""
    def __init__(self):
        self.binaries = {}


    def load_binaries(self, directory):
        """Load all binaries' reports from given directory."""
        for f in os.listdir(directory):
            self.binaries[f] = Instance()
            self.binaries[f].load_json(directory+"/"+f)
            self.binaries[f].label_sample()
            self.binaries[f].extract_features()
            self.binaries[f].extract_basic_features()


    def get_labels(self):
        """Return binary labels as a labelled dictionary."""
        labels = {}
        for i in self.binaries:
            labels[i] = self.binaries[i].label
        return labels


    def get_features(self):
        """Return complex binary features as a labelled dictionary."""
        features = {}
        for i in self.binaries:
            features[i] = self.binaries[i].features
        return features


    def get_simple_features(self):
        """Return simplified binary features as a labelled dictionary."""
        simple_features = {}
        for i in self.binaries:
            simple_features[i] = self.binaries[i].basic_features
        return simple_features


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
        self.features = {}
        self.basic_features = {}


    def load_json(self, json_file):
        """Load JSON formatted malware report. It can handle both a path to
        JSON file and a dictionary object."""
        if isinstance(json_file, str):
            with open(json_file, "r") as malware_report:
                try:
                    self.report = json.load(malware_report)
                except ValueError, error:
                    print >> sys.stderr, "Could not load file;", \
                        malware_report, "is not a valid JSON file."
                    print >> sys.stderr, "Exception: %s" % str(error)
                    sys.exit(1)
        elif isinstance(json_file, dict):
            self.report = json_file
        else:
            # Unknown binary format
            print >> sys.stderr, "Could not load the data *", json, "* is of " \
                "unknown type: ", type(json), "."

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
        # Get binary size
        self.features["size"] = \
            self.report.get("target", {}).get("file", {}).get("size")

        # Get binary timestamp in the UNIX timestamp format
        str_dt = self.report.get("static", {}).get("pe_timestamp")
        ts = None
        if str_dt is not None:
            dt = datetime.datetime.strptime(str_dt, "%Y-%m-%d %H:%M:%S")
            ts = int(time.mktime(dt.timetuple()))
        self.features["timestamp"] = ts

        # ExifTool output
        et_tokens = ["FileDescription", "OriginalFilename"]
        for token in et_tokens:
            self.features[token] = None
        for attr in self.report.get("static", {}).get("pe_versioninfo", []):
            attr_name = attr.get("name")
            if attr_name in et_tokens:
                self.features[attr_name] = attr.get("value")

        # Magic byte
        self.features["magic_byte"] = \
            self.report.get("target", {}).get("file", {}).get("type")


    def feature_static_signature(self):
        """Create features form binary signature check."""
        # Check availability of digital signature
        self.features["signed"] = \
            bool(self.report.get("static", {}).get("signature", []))

        # ExifTool output
        et_tokens = ["Comments", "ProductName", "LegalCopyright", \
                     "InternalName", "CompanyName"]
        for token in et_tokens:
            self.features[token] = None
        for attr in self.report.get("static", {}).get("pe_versioninfo", []):
            attr_name = attr.get("name")
            if attr_name in et_tokens:
                self.features[attr_name] = attr.get("value")


    def feature_static_heuristic(self):
        """Create features form results return by heuristic tools.
        **Not available for current JSON content.**"""
        pass


    def feature_static_packer(self):
        """Create feature from information returned by packer/cryptor
        detectors."""
        self.features["packer"] = \
            self.report.get("static", {}).get("peid_signatures", None)


    def feature_static_pef(self):
        """Create features from information derived form portable executable
        format."""
        # Get resource languages
        self.features["languages"] = []
        for d in self.report.get("static", {}).get("pe_resources", []):
            lang = d.get("language", False)
            if lang:
                if lang.startswith("LANG_"):
                    lang = lang[5:]
                else:
                    lang = lang
                if lang not in self.features["languages"]:
                    self.features["languages"].append(lang)
            sublang = d.get("sublanguage", False)
            if sublang:
                if sublang.startswith("SUBLANG_"):
                    sublang = sublang[8:]
                else:
                    sublang = sublang
                if sublang not in self.features["languages"]:
                    self.features["languages"].append(sublang)

        # Section and resource attributes
        self.features["section_attrs"] = {}
        for d in self.report.get("static", {}).get("pe_sections", []):
            n = d.get("name")
            e = d.get("entropy")
            if n and d:
                self.features["section_attrs"][n] = e
        self.features["resource_attrs"] = {}
        for d in self.report.get("static", {}).get("pe_resources", []):
            n = d.get("name")
            f = d.get("filetype")
            if n and f:
                self.features["resource_attrs"][n] = f


    def feature_static_imports(self):
        """Extract features from static imports like referenced library
        functions."""
        self.features["static_imports"] = {}

        # Static libraries import count
        self.features["static_imports"]["count"] = \
            self.report.get("static", {}).get("imported_dll_count", None)

        # Get all imported libraries
        for d in self.report.get("static", {}).get("pe_imports", []):
            ddl_name = d.get("dll")
            if not ddl_name:
                continue
            self.features["static_imports"][ddl_name] = []
            for i in d.get("imports", []):
                ref = i.get("name")
                if ref is not None:
                    self.features["static_imports"][ddl_name].append(ref)


    def feature_dynamic_imports(self):
        """Extract features from dynamic imports, mutexes, and processes."""
        # Get mutexes
        self.features["mutex"] = \
            self.report.get("behavior", {}).get("summary", {}).get("mutex")

        # Get processes names
        self.features["processes"] = []
        for p in self.report.get("behavior", {}).get("processes", []):
            p_name = p.get("process_name")
            if p_name and p_name not in self.features["processes"]:
                self.features["processes"].append(p_name)

        # Get dynamically loaded library names
        self.features["dynamic_imports"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("dll_loaded", [])


    def feature_dynamic_filesystem(self):
        """Extract features from filesystem operations."""
        def flatten_list(structured):
            """Flatten nested list."""
            flat = []
            for i in structured:
                flat += i
            return flat

        # Get file operations and their number
        self.features["file_read"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_read", [])
        self.features["files_read"] = len(self.features["file_read"])
        self.features["file_written"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_written", [])
        self.features["files_written"] = len(self.features["file_written"])
        self.features["file_deleted"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_deleted", [])
        self.features["files_deleted"] = len(self.features["file_deleted"])
        self.features["file_copied"] = flatten_list(\
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_copied", [])
                                                   )
        self.features["files_copied"] = len(\
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_copied", [])
                                            )
        self.features["file_renamed"] = flatten_list(\
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_moved", [])
                                                    )
        self.features["files_renamed"] = len(self.features["file_renamed"])

        # Get other file operations numbers
        self.features["files_opened"] = len(
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_opened", [])
        )
        self.features["files_exists"] = len(
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_exists", [])
        )
        self.features["files_failed"] = len(
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_failed", [])
        )

        # Get total number of unique touched files
        file_operations = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_read", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_written", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_deleted", []) + \
            flatten_list(self.report.get("behavior", {}).get("summary", {})\
            .get("file_copied", [])) + \
            flatten_list(self.report.get("behavior", {}).get("summary", {})\
            .get("file_moved", [])) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_recreated", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_opened", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_exists", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_failed", [])
        # remove duplicates
        self.features["files_operations"] = len(list(set(file_operations)))


    def feature_dynamic_network(self):
        """Extract features from network operations."""
        # Get TCP IP addresses
        self.features["tcp"] = []
        for c in self.report.get("network", {}).get("tcp", []):
            c_dst = c.get("dst")
            if c_dst and c_dst not in self.features["tcp"]:
                self.features["tcp"].append(c_dst)

        # Get UDP IPs
        self.features["udp"] = []
        for c in self.report.get("network", {}).get("udp", []):
            c_dst = c.get("dst")
            if c_dst and c_dst not in self.features["udp"]:
                self.features["udp"].append(c_dst)

        # Get DNS queries and responses
        self.features["dns"] = {}
        for c in self.report.get("network", {}).get("dns", []):
            request = c.get("request")
            if request:
                self.features["dns"][request] = []
            else:
                continue

            answers = c.get("answers", [])
            for a in answers:
                a_type = a.get("type")
                a_data = a.get("data")
                if a_type == "A" and a_data:
                    self.features["dns"][request].append(a_data)

        # Get HTTP requests: method, host, port, path
        self.features["http"] = {}
        for c in self.report.get("network", {}).get("http", []):
            c_data = c.get("data")
            if c_data:
                self.features["http"][c_data] = {}
            else:
                continue

            c_method = c.get("method")
            if c_method:
                self.features["http"][c_data]["method"] = c_method
            c_host = c.get("host")
            if c_host:
                self.features["http"][c_data]["host"] = c_host
            c_port = c.get("port")
            if c_port:
                self.features["http"][c_data]["port"] = c_port


    def feature_dynamic_registry(self):
        """Extract features from registry operations."""
        # Registry written
        self.features["regkey_written"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("regkey_written", [])
        # Registry delete
        self.features["regkey_deleted"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("regkey_deleted", [])


    def feature_dynamic_windowsapi(self):
        """Extract features from Windows API calls sequence."""
        self.features["api_stats"] = {}
        apistats = self.report.get("behavior", {}).get("apistats", {})
        for d in apistats:
            for e in apistats[d]:
                if e in self.features["api_stats"]:
                    self.features["api_stats"][e] += apistats[d][e]
                else:
                    self.features["api_stats"][e] = apistats[d][e]


    def extract_basic_features(self):
        """Extract very basic set of features from *signatures* JSON field.
        These are extracted characteristics of the binary by cuckoo sandbox."""
        if self.basic_features:
            self.basic_features = {}

        for s in self.report.get("signatures", []):
            name = s.get("name", "")
            description = s.get("description", "")
            if name:
                self.basic_features[name] = description
                continue
            if description:
                self.basic_features[hash(description)] = description
