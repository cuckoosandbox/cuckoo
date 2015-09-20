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

        # Build server random -> session id from the pcap information.
        if "network" in self.results and "tls" in self.results["network"]:
            for row in self.results["network"]["tls"]:
                metakeys[row["server_random"]] = row["session_id"]

        results = {}

        # Fetch all key information from the behavior logs.
        for process in self.results.get("behavior", {}).get("processes", []):
            if process["process_name"] != "lsass.exe":
                continue

            for call in process["calls"]:
                args = call["arguments"]
                if call["api"] != "PRF" or args["type"] != "key expansion":
                    continue

                if args["server_random"] not in metakeys:
                    continue

                # We keep the results in a dictionary before writing them out
                # to a file in order to avoid duplicates (in an easy way).
                results[metakeys[args["server_random"]]] = \
                    args["master_secret"]

        with open(self.tlsmaster_path, "wb") as f:
            for session_id, master_secret in sorted(results.items()):
                print>>f, "RSA Session-ID:%s Master-Key:%s" % (
                    session_id, master_secret)
