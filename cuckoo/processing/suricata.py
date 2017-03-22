# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import shutil
import subprocess
import time

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.files import Files

try:
    import suricatasc
    HAVE_SURICATASC = True
except ImportError:
    HAVE_SURICATASC = False

log = logging.getLogger(__name__)

class Suricata(Processing):
    """Suricata processing module."""

    # List of Suricata Signatures IDs that should be ignored.
    sid_blacklist = [
        # SURICATA FRAG IPv6 Fragmentation overlap
        2200074,

        # ET INFO InetSim Response from External Source Possible SinkHole
        2017363,

        # SURICATA UDPv4 invalid checksum
        2200075,
    ]

    def process_pcap_socket(self):
        """Process a PCAP file with Suricata in socket mode."""
        if not HAVE_SURICATASC:
            raise CuckooProcessingError(
                "Suricata has been configured to run in socket mode but "
                "suricatasc has not been installed, please re-install "
                "Suricata or SuricataSC"
            )

        if not os.path.exists(self.socket):
            raise CuckooProcessingError(
                "Suricata has been configured to run in socket mode "
                "but the socket is unavailable"
            )

        suri = suricatasc.SuricataSC(self.socket)

        try:
            suri.connect()
        except suricatasc.SuricataException as e:
            raise CuckooProcessingError(
                "Error connecting to Suricata in socket mode: %s" % e
            )

        # Submit the PCAP file.
        ret = suri.send_command("pcap-file", {
            "filename": self.pcap_path,
            "output-dir": self.suricata_path,
        })

        if not ret or ret["return"] != "OK":
            raise CuckooProcessingError(
                "Error submitting PCAP file to Suricata in socket mode, "
                "return value: %s" % ret
            )

        # TODO Should we add a timeout here? If we do so we should also add
        # timeout logic to the binary mode.
        while True:
            ret = suri.send_command("pcap-current")

            # When the pcap file has been processed the "current pcap" file
            # will be none.
            if ret and ret["message"] == "None":
                break

            time.sleep(1)

    def process_pcap_binary(self):
        """Process a PCAP file with Suricata by running Suricata.

        Using the socket mode is preferred as the plain binary mode requires
        Suricata to load all its rules for every PCAP file and thus takes a
        couple of performance heavy seconds to set itself up.
        """
        if not os.path.isfile(self.suricata):
            raise CuckooProcessingError("Unable to locate Suricata binary")

        if not os.path.isfile(self.config_path):
            raise CuckooProcessingError(
                "Unable to locate Suricata configuration"
            )

        args = [
            self.suricata,
            "-c", self.config_path,
            "-k", "none",
            "-l", self.suricata_path,
            "-r", self.pcap_path,
        ]

        try:
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            raise CuckooProcessingError(
                "Suricata returned an error processing this pcap: %s" % e
            )

    def parse_eve_json(self):
        """Parse the eve.json file."""
        eve_log = os.path.join(self.suricata_path, self.eve_log)
        if not os.path.isfile(eve_log):
            log.warning("Unable to find the eve.json log file")
            return

        for line in open(eve_log, "rb"):
            event = json.loads(line)

            if event["event_type"] == "alert":
                alert = event["alert"]

                if alert["signature_id"] in self.sid_blacklist:
                    log.debug(
                        "Ignoring alert with sid=%d, signature=%s",
                        alert["signature_id"], alert["signature"]
                    )
                    continue

                if alert["signature"].startswith("SURICATA STREAM"):
                    log.debug(
                        "Ignoring alert starting with \"SURICATA STREAM\""
                    )
                    continue

                self.results["alerts"].append({
                    "sid": alert["signature_id"],
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dst_ip": event["dest_ip"],
                    "dst_port": event.get("dest_port"),
                    "protocol": event.get("proto"),
                    "timestamp": event.get("timestamp"),
                    "category": alert.get("category") or "undefined",
                    "signature": alert["signature"],
                })

            elif event["event_type"] == "http":
                http = event["http"]

                referer = http.get("http_referer")
                if referer == "<unknown>":
                    referer = None

                user_agent = http.get("http_user_agent")
                if user_agent == "<unknown>":
                    user_agent = None

                self.results["http"].append({
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dst_ip": event.get("dest_ip"),
                    "dst_port": event.get("dest_port"),
                    "timestamp": event.get("timestamp"),
                    "method": http.get("http_method"),
                    "hostname": http.get("hostname"),
                    "url": http.get("url"),
                    "status": "%s" % http.get("status"),
                    "content_type": http.get("http_content_type"),
                    "user_agent": user_agent,
                    "referer": referer,
                    "length": http.get("length"),
                })

            elif event["event_type"] == "tls":
                tls = event["tls"]

                self.results["tls"].append({
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dst_ip": event.get("dest_ip"),
                    "dst_port": event.get("dest_port"),
                    "timestamp": event.get("timestamp"),
                    "fingerprint": tls.get("fingerprint"),
                    "issuer": tls.get("issuerdn"),
                    "version": tls.get("version"),
                    "subject": tls.get("subject"),
                })

    def parse_files(self):
        """Parse the files-json.log file and its associated files."""
        files_log = os.path.join(self.suricata_path, self.files_log)
        if not os.path.isfile(files_log):
            log.warning("Unable to find the files-json.log log file")
            return

        files = {}

        # Index all the available files.
        files_dir = os.path.join(self.suricata_path, self.files_dir)
        if not os.path.exists(files_dir):
            log.warning("Suricata files dir is not available. Maybe you forgot to enable Suricata file-store ?")
            return

        for filename in os.listdir(files_dir):
            filepath = os.path.join(files_dir, filename)
            files[Files.md5_file(filepath)] = filepath

        for line in open(files_log, "rb"):
            event = json.loads(line)

            # Not entirely sure what's up, but some files are given just an
            # ID, some files are given just an md5 hash (and maybe some get
            # neither?) So take care of these situations.
            if "id" in event:
                filepath = os.path.join(files_dir, "file.%s" % event["id"])
            elif "md5" in event:
                filepath = files.get(event["md5"])
            else:
                filepath = None

            if not filepath or not os.path.isfile(filepath):
                log.warning(
                    "Suricata dropped file with id=%s and md5=%s not found, "
                    "skipping it..", event.get("id"), event.get("md5")
                )
                continue

            referer = event.get("http_referer")
            if referer == "<unknown>":
                referer = None

            self.results["files"].append({
                "id": int(filepath.split(".", 1)[-1]),
                "filesize": event["size"],
                "filename": os.path.basename(event["filename"]),
                "hostname": event.get("http_host"),
                "uri": event.get("http_uri"),
                "md5": Files.md5_file(filepath),
                "sha1": Files.sha1_file(filepath),
                "magic": event.get("magic"),
                "referer": referer,
            })

    def run(self):
        self.key = "suricata"

        self.results = {
            "alerts": [],
            "tls": [],
            "files": [],
            "http": [],
        }

        self.suricata = self.options.get("suricata", "/usr/bin/suricata")
        self.config_path = self.options.get("conf", "/etc/suricata/suricata.yaml")
        self.eve_log = self.options.get("eve_log", "eve.json")
        self.files_log = self.options.get("files_log", "files-json.log")
        self.files_dir = self.options.get("files_dir", "files")

        # Determines whether we're in socket more or binary mode.
        self.socket = self.options.get("socket")

        if not os.path.isfile(self.pcap_path):
            log.warning("Unable to run Suricata as no pcap is available")
            return self.results

        # Remove any existing Suricata related log-files before we
        # run Suricata again. I.e., prevent reprocessing an analysis from
        # generating duplicate results.
        if os.path.isdir(self.suricata_path):
            shutil.rmtree(self.suricata_path)

        os.mkdir(self.suricata_path)

        if self.socket:
            self.process_pcap_socket()
        else:
            self.process_pcap_binary()

        self.parse_eve_json()
        self.parse_files()

        return self.results
