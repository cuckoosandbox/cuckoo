# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Processing

class TLSMasterSecrets(Processing):
    """Cross-references TLS master secrets extracted from the monitor and key
    information extracted from the PCAP to dump a master secrets file
    compatible with, e.g., Wireshark."""

    order = 2
    key = "dumptls"

    def run(self):
        metakeys = {}

        # Build server random <-> session id mapping from the PCAP.
        if "network" in self.results and "tls" in self.results["network"]:
            for row in self.results["network"]["tls"]:
                metakeys[row["server_random"]] = row["session_id"]

        results = {}

        # Build server random <-> master secret mapping from behavioral logs.
        summary = self.results.get("behavior", {}).get("summary", {})
        for entry in summary.get("tls_master", []):
            client_random, server_random, master_secret = entry
            results[metakeys[server_random]] = master_secret

        # Write the tls master secrets file.
        with open(self.tlsmaster_path, "wb") as f:
            for session_id, master_secret in sorted(results.items()):
                print>>f, "RSA Session-ID:%s Master-Key:%s" % (
                    session_id, master_secret)
